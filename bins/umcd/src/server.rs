//! Control socket server: Unix stream socket, framing, connection handling,
//! and the service-backed envelope dispatcher (control-api.md §16-24).
use crate::config::NodeConfig;
use crate::doctor;
use crate::relay_service::CircuitOpenRequest;
use crate::runtime_adapters::OsEntropy;
use crate::state::{metric_names, wall_now, IdentityRef, RuntimeState, NODE_IDENTITY_RECORD};
use prost::Message;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use umc_bundle::envelope::seal_bundle;
use umc_bundle::manager::BundleStatus;
use umc_carrier::Carrier;
use umc_control::conn::SequenceTracker;
use umc_control::framing::{frame_envelope, EnvelopeDecoder};
use umc_control::pages::PageToken;
use umc_control::proto::umc::api::v1 as api;
use umc_core::block::BlockReason;
use umc_core::trust::TrustState;
use umc_discovery::invitation::InvitationError;
use umc_discovery::provider::{CandidateAuth, CandidateSource, PeerCandidate, SharingPolicy};
use umc_routing::types::{RouteKey, RouteScope, RouteState};
use umc_storage::records;
use umc_storage::sqlite::SqliteStore;
use umc_storage::store::{Namespace, Store};
use umc_types::runtime::Instant;

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

/// Wire body of the `PeerService.CreateInvitation` invitation document
/// (discovery.md §14): the proto `InvitationScope` does not carry the
/// invitation id, and `ImportInvitationRequest` carries only the document
/// and the secret — so the document embeds the id next to the scope.
#[derive(Clone, PartialEq, prost::Message)]
struct InvitationDocument {
    #[prost(bytes, tag = "1")]
    invitation_id: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    scope: Option<api::InvitationScope>,
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

/// Wire request for `CarrierService.GetLinkProperties` (task F2): the
/// capability report for one registered carrier type. No proto message
/// exists yet, so the control surface carries the carrier type id until
/// the API spec gains the method.
#[derive(Clone, PartialEq, prost::Message)]
struct GetLinkPropertiesRequest {
    #[prost(string, tag = "1")]
    carrier_type: String,
}

/// Wire response for `CarrierService.GetLinkProperties` (task F2).
#[derive(Clone, PartialEq, prost::Message)]
struct GetLinkPropertiesResponse {
    #[prost(message, optional, tag = "1")]
    info: Option<api::CarrierTypeInfo>,
}

/// One per-carrier session count for `CarrierService.GetLinkStats`
/// (task F2): the v1 registry's only per-carrier statistic.
#[derive(Clone, PartialEq, prost::Message)]
struct LinkStats {
    #[prost(string, tag = "1")]
    carrier_type: String,
    #[prost(uint32, tag = "2")]
    active_links: u32,
}

/// Wire response for `CarrierService.GetLinkStats` (task F2).
#[derive(Clone, PartialEq, prost::Message)]
struct GetLinkStatsResponse {
    #[prost(message, repeated, tag = "1")]
    stats: Vec<LinkStats>,
}

/// Wire request for `CarrierService.Listen` (task F2): bind one registered
/// carrier at an explicit address. No proto message exists yet.
#[derive(Clone, PartialEq, prost::Message)]
struct ListenRequest {
    #[prost(string, tag = "1")]
    carrier_type: String,
    #[prost(string, tag = "2")]
    bind_address: String,
}

/// Wire response for `CarrierService.Listen` (task F2): the requested bind
/// address. The `Listener` trait exposes no kernel-assigned address, so an
/// ephemeral port (`127.0.0.1:0`) is reported as requested, not as bound.
#[derive(Clone, PartialEq, prost::Message)]
struct ListenResponse {
    #[prost(string, tag = "1")]
    bound_address: String,
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
    let mut event_tick = tokio::time::interval(Duration::from_millis(25));
    loop {
        tokio::select! {
            read_result = stream.read(&mut buf) => {
                let Ok(n) = read_result else {
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
            }
            _ = event_tick.tick(), if !conn.subscriptions.is_empty() => {
                let events = {
                    let mut state = state.lock().expect("runtime state");
                    drain_event_envelopes(&mut state, &mut conn)
                };
                for event in events {
                    let mut encoded = Vec::new();
                    Message::encode(&event, &mut encoded).expect("encode event envelope");
                    let mut out = Vec::new();
                    if frame_envelope(&mut out, &encoded, DEFAULT_ENVELOPE_MAX).is_ok() {
                        let _ = stream.write_all(&out).await;
                    }
                }
            }
        }
        if conn.draining {
            // GoAway: the current batch drained; close the connection
            // (control-api.md §6.4).
            log::info!("[control] connection drained after go-away, closing");
            break;
        }
    }
    if !conn.subscriptions.is_empty() {
        let state = state.lock().expect("runtime state");
        let mut bus = state.event_bus.lock().expect("event bus");
        for subscription_id in conn.subscriptions.keys() {
            bus.unsubscribe(*subscription_id);
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
    subscriptions: HashMap<u64, api::EventFilter>,
    next_server_sequence: u64,
}

impl ConnectionState {
    #[must_use]
    fn new() -> Self {
        Self {
            presented_token: None,
            sequences: SequenceTracker::new(),
            draining: false,
            idempotent: IdempotencyCache::new(),
            subscriptions: HashMap::new(),
            next_server_sequence: 1,
        }
    }

    fn next_server_sequence(&mut self) -> u64 {
        let sequence = self.next_server_sequence;
        self.next_server_sequence = self.next_server_sequence.saturating_add(1);
        sequence
    }
}

/// Bounded per-connection idempotency replay cache (control-api.md §18):
/// `(request_id, idempotency_key)` → stored response bytes, 10-minute TTL,
/// FIFO eviction at 1,024 entries. A replay returns the stored bytes
/// without re-dispatching.
/// Idempotency key: (service, method, client key) — scoped per
/// control-api.md §18.
type IdempotencyKey = (String, String, Vec<u8>);

#[derive(Debug, Default)]
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
                let presented_token = conn.presented_token.clone();
                let response =
                    dispatch_connection_request(conn, state, &request, presented_token.as_deref());
                conn.idempotent.insert(key, response.clone(), now_ms);
                return Some(response);
            }
            {
                let presented_token = conn.presented_token.clone();
                Some(dispatch_connection_request(
                    conn,
                    state,
                    &request,
                    presented_token.as_deref(),
                ))
            }
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

/// Dispatch a request that may create or consume a connection-owned event
/// subscription. All other services retain the ordinary stateless dispatch
/// path used by unit tests and the control API.
fn dispatch_connection_request(
    conn: &mut ConnectionState,
    state: &mut RuntimeState,
    request: &api::Request,
    presented_token: Option<&[u8]>,
) -> Vec<u8> {
    if request.service == "EventService" {
        dispatch_event_request(conn, state, request, presented_token)
    } else if request.service == "TokenService" && request.method == "InspectCurrentGrant" {
        if let Some(configured) = &state.development_token {
            let authorized = presented_token.is_some_and(|token| token == configured.as_slice());
            if !authorized {
                return response_envelope(request, api::StatusCode::Unauthenticated as i32, None);
            }
        }
        let (code, payload) = inspect_current_grant(state, request, presented_token);
        response_envelope(request, code, payload)
    } else {
        dispatch_request(state, request, presented_token)
    }
}

fn dispatch_event_request(
    conn: &mut ConnectionState,
    state: &mut RuntimeState,
    request: &api::Request,
    presented_token: Option<&[u8]>,
) -> Vec<u8> {
    if let Some(configured) = &state.development_token {
        let authorized = presented_token.is_some_and(|token| token == configured.as_slice());
        if !authorized {
            return response_envelope(request, api::StatusCode::Unauthenticated as i32, None);
        }
    }
    let (code, payload) = match request.method.as_str() {
        "Subscribe" => subscribe_events(conn, state, request),
        "Unsubscribe" => unsubscribe_events(conn, state, request),
        _ => (api::StatusCode::Unimplemented as i32, None),
    };
    response_envelope(request, code, payload)
}

fn subscribe_events(
    conn: &mut ConnectionState,
    state: &mut RuntimeState,
    request: &api::Request,
) -> (i32, Option<Vec<u8>>) {
    let Ok(subscribe) = api::SubscribeRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if !subscribe.resume_cursor.is_empty() {
        return (api::StatusCode::OutOfRange as i32, None);
    }
    if conn.subscriptions.len() >= umc_control::events::MAX_EVENT_STREAMS_PER_CLIENT {
        return (api::StatusCode::ResourceExhausted as i32, None);
    }
    let filter = subscribe.filter.unwrap_or_default();
    let initial = if filter.include_initial_snapshot {
        Some(state.events.lock().expect("event log").recent(100))
    } else {
        None
    };
    let subscription_id = {
        let mut bus = state.event_bus.lock().expect("event bus");
        let id = bus.subscribe();
        if let Some(initial) = initial {
            if let Some(subscription) = bus.subscription(id) {
                for event in initial.into_iter().rev() {
                    let _ = subscription.push(crate::event_log::to_control_event(&event));
                }
            }
        }
        id
    };
    conn.subscriptions.insert(subscription_id, filter);
    let handle = subscription_id.to_be_bytes().to_vec();
    let response = api::SubscribeResponse {
        subscription_handle: Some(api::OpaqueHandle {
            value: handle.clone(),
        }),
        resume_cursor: handle,
        first_event_sequence: 1,
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn unsubscribe_events(
    conn: &mut ConnectionState,
    state: &mut RuntimeState,
    request: &api::Request,
) -> (i32, Option<Vec<u8>>) {
    let Ok(unsubscribe) = api::UnsubscribeRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = unsubscribe.subscription_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(id_bytes) = <[u8; 8]>::try_from(handle.value.as_slice()) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let id = u64::from_be_bytes(id_bytes);
    if conn.subscriptions.remove(&id).is_none() {
        return (api::StatusCode::NotFound as i32, None);
    }
    state.event_bus.lock().expect("event bus").unsubscribe(id);
    let mut payload = Vec::new();
    Message::encode(&api::UnsubscribeResponse {}, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn drain_event_envelopes(
    state: &mut RuntimeState,
    conn: &mut ConnectionState,
) -> Vec<api::Envelope> {
    let subscriptions: Vec<(u64, api::EventFilter)> = conn
        .subscriptions
        .iter()
        .map(|(id, filter)| (*id, filter.clone()))
        .collect();
    let mut bus = state.event_bus.lock().expect("event bus");
    let mut envelopes = Vec::new();
    for (id, filter) in subscriptions {
        let Some(subscription) = bus.subscription(id) else {
            continue;
        };
        while let Some((sequence, event)) = subscription.pop_with_sequence() {
            if !event_matches_filter(&event, &filter) {
                continue;
            }
            envelopes.push(api::Envelope {
                api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
                sequence: conn.next_server_sequence(),
                body: Some(api::envelope::Body::Event(api::Event {
                    subscription_handle: Some(api::OpaqueHandle {
                        value: id.to_be_bytes().to_vec(),
                    }),
                    event_sequence: sequence,
                    event_type: event_type_code(&event.event_type),
                    event_class: event_class_code(event.class),
                    occurred_at_unix_ms: i64::try_from(event.occurred_at_ms).unwrap_or(i64::MAX),
                    resource_handle: None,
                    resource_id: event.resource.unwrap_or_default(),
                    payload_type: event.event_type,
                    payload: event.payload,
                    resume_cursor: id.to_be_bytes().to_vec(),
                })),
            });
        }
    }
    envelopes
}

fn event_matches_filter(event: &umc_control::events::UmpEvent, filter: &api::EventFilter) -> bool {
    let event_type = event_type_code(&event.event_type);
    if !filter.event_types.is_empty() && !filter.event_types.contains(&event_type) {
        return false;
    }
    if !filter.resource_handles.is_empty() || !filter.endpoint_ids.is_empty() {
        return false;
    }
    let minimum = filter.minimum_severity;
    minimum == 0 || event_severity(event.class) >= minimum
}

fn event_severity(class: umc_control::events::EventClass) -> i32 {
    match class {
        umc_control::events::EventClass::Critical => api::DiagnosticSeverity::Critical as i32,
        umc_control::events::EventClass::State => api::DiagnosticSeverity::Warning as i32,
        umc_control::events::EventClass::Edge | umc_control::events::EventClass::Sample => {
            api::DiagnosticSeverity::Info as i32
        }
    }
}

fn event_class_code(class: umc_control::events::EventClass) -> i32 {
    match class {
        umc_control::events::EventClass::Critical => api::EventClass::Critical as i32,
        umc_control::events::EventClass::State => api::EventClass::State as i32,
        umc_control::events::EventClass::Edge => api::EventClass::Edge as i32,
        umc_control::events::EventClass::Sample => api::EventClass::Sample as i32,
    }
}

fn event_type_code(kind: &str) -> i32 {
    match kind {
        "session_active" | "session_closed" => api::EventType::SessionState as i32,
        "path_degraded" => api::EventType::PathChanged as i32,
        "bundle_admitted" | "bundle_expired" => api::EventType::BundleState as i32,
        "circuit_opened" | "circuit_closed" | "relay_data_forwarded" => {
            api::EventType::RelayState as i32
        }
        "application_registered" | "application_unregistered" => api::EventType::NodeState as i32,
        "peer_blocked" | "peer_unblocked" | "trust_state_set" => api::EventType::PeerChanged as i32,
        _ => api::EventType::Audit as i32,
    }
}

fn create_token(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(create) = api::CreateTokenRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if create.expires_at_unix_ms < 0 {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let expires_at_ms = match u64::try_from(create.expires_at_unix_ms) {
        Ok(0) => None,
        Ok(value) => Some(value),
        Err(_) => return (api::StatusCode::InvalidArgument as i32, None),
    };
    let (principal_id, token) = state.token_registry.create_token(expires_at_ms, &OsEntropy);
    let grants = create.grants;
    state.token_grants.insert(principal_id, grants.clone());
    let response = api::CreateTokenResponse {
        token_id: principal_id.to_be_bytes().to_vec(),
        token,
        effective_grants: grants,
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn list_grants(
    state: &RuntimeState,
    request: &api::Request,
    current_principal: u64,
) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListGrantsRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let principal_id = if list.principal_id.is_empty() {
        current_principal
    } else {
        let Ok(bytes) = <[u8; 8]>::try_from(list.principal_id.as_slice()) else {
            return (api::StatusCode::InvalidArgument as i32, None);
        };
        u64::from_be_bytes(bytes)
    };
    let Ok((offset, page_size)) = page_window(list.page.as_ref(), "ListGrants") else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let all = state
        .token_grants
        .get(&principal_id)
        .cloned()
        .unwrap_or_default();
    let total = all.len();
    let grants = all.into_iter().skip(offset).take(page_size).collect();
    let response = api::ListGrantsResponse {
        grants,
        page: Some(page_info(total, offset, page_size, "ListGrants")),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn revoke_token(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(revoke) = api::RevokeTokenRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(bytes) = <[u8; 8]>::try_from(revoke.token_id.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let principal_id = u64::from_be_bytes(bytes);
    let existed = state.token_registry.revoke(principal_id);
    state.token_grants.remove(&principal_id);
    if !existed {
        return (api::StatusCode::NotFound as i32, None);
    }
    let mut payload = Vec::new();
    Message::encode(&api::RevokeTokenResponse {}, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn inspect_current_grant(
    state: &RuntimeState,
    request: &api::Request,
    presented_token: Option<&[u8]>,
) -> (i32, Option<Vec<u8>>) {
    if api::InspectCurrentGrantRequest::decode(request.payload.as_slice()).is_err() {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let principal_id = presented_token
        .and_then(|token| state.token_registry.authenticate(token, wall_now().0).ok())
        .unwrap_or(0);
    let response = api::InspectCurrentGrantResponse {
        principal_id: if principal_id == 0 {
            Vec::new()
        } else {
            principal_id.to_be_bytes().to_vec()
        },
        grants: state
            .token_grants
            .get(&principal_id)
            .cloned()
            .unwrap_or_default(),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// Service-backed envelope dispatch (control-api.md §16-24). Methods without
/// a service implementation return `Unimplemented`.
///
/// When the daemon is configured with a development token, requests whose
/// connection did not present that exact token at hello time are rejected
/// with `Unauthenticated` before dispatch (control-api.md §11.3).
// One flat match table per service (the same shape as the spec's method
// list); the per-service arms are each a line.
#[allow(clippy::too_many_lines)]
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
        "IdentityService" => metric_names::CONTROL_REQUESTS_IDENTITY,
        "CarrierService" => metric_names::CONTROL_REQUESTS_CARRIER,
        "ApplicationService" => metric_names::CONTROL_REQUESTS_APP,
        _ => metric_names::CONTROL_REQUESTS_OTHER,
    };
    state.metrics.incr(service_counter, 1);
    let (code, payload) = match (request.service.as_str(), request.method.as_str()) {
        ("NodeAdmin", "GetStatus") => get_status(state),
        ("PeerService" | "DiscoveryService", "ListCandidates") => list_candidates(state),
        ("PeerService", "ListPeers") => list_peers(state, request),
        ("PeerService", "GetPeer") => get_peer(state, request),
        ("PeerService", "AddPeerHint") => add_peer_hint(state, request),
        ("PeerService", "RemovePeer") => remove_peer(state, request),
        ("PeerService", "SetTrustState") => set_trust_state(state, request),
        ("PeerService", "BlockPeer") => block_peer(state, request),
        ("PeerService", "UnblockPeer") => unblock_peer(state, request),
        ("PeerService", "CreateInvitation") => create_invitation(state, request),
        ("PeerService", "ImportInvitation") => import_invitation(state, request),
        ("PeerService", "RevokeInvitation") => revoke_invitation(state, request),
        ("SessionService", "ListSessions") => list_sessions(state, request),
        ("SessionService", "GetSession") => get_session(state, request),
        ("SessionService", "CloseSession") => close_session(state, request),
        ("SessionService", "ListStreams") => list_streams(state, request),
        ("RouteService", "ListRoutes") => list_routes(state, request),
        ("RouteService", "GetRoute") => get_route(state, request),
        ("RouteService", "ProbeRoute") => probe_route(state, request),
        ("RouteService", "InvalidateRoute") => invalidate_route(state, request),
        ("BundleService", "GetBundles" | "ListBundles") => list_bundles(state, request),
        ("BundleService", "CreateBundle") => create_bundle(state, request),
        ("BundleService", "GetBundle") => get_bundle(state, request),
        ("BundleService", "DeleteBundle") => delete_bundle(state, request),
        ("RelayService", "OpenCircuit") => open_circuit(state, request),
        ("RelayService", "CloseCircuit") => close_circuit(state, request),
        ("RelayService", "GetRelayStatus") => get_relay_status(state, request),
        ("RelayService", "UpdateRelayPolicy") => update_relay_policy(state, request),
        ("RelayService", "ListRelayCircuits") => list_relay_circuits(state, request),
        ("RelayService", "CloseRelayCircuit") => close_relay_circuit(state, request),
        ("NodeAdmin" | "ConfigService", "GetConfig") => get_config(state),
        ("NodeAdmin", "GetEvents") => get_events(state),
        ("DiagnosticsService" | "NodeAdmin", "RunDoctor" | "Doctor") => run_doctor(state),
        ("DiagnosticsService", "GetMetricsSnapshot") => get_metrics_snapshot(state, request),
        ("DiagnosticsService", "GetSubsystemHealth") => get_subsystem_health(state, request),
        ("TokenService", "ListGrants") => list_grants(state, request, 0),
        ("TokenService", "CreateToken") => create_token(state, request),
        ("TokenService", "RevokeToken") => revoke_token(state, request),
        ("TokenService", "InspectCurrentGrant") => inspect_current_grant(state, request, None),
        ("ConfigService", "SetConfig") | ("NodeAdmin", "UpdateConfig") => {
            set_config(state, request)
        }
        // IdentityService (task F2): all nine proto RPCs have runtime
        // backing — the keystore-backed identity registry in state.rs.
        ("IdentityService", "ListIdentities") => list_identities(state, request),
        ("IdentityService", "GetIdentity") => get_identity(state, request),
        ("IdentityService", "CreateIdentity") => create_identity(state, request),
        ("IdentityService", "RotateHandshakeKey") => rotate_handshake_key(state, request),
        ("IdentityService", "RotateIdentityKey") => rotate_identity_key(state, request),
        ("IdentityService", "ExportPublicIdentity") => export_public_identity(state, request),
        ("IdentityService", "ExportSecretIdentity") => export_secret_identity(state, request),
        ("IdentityService", "ImportIdentity") => import_identity(state, request),
        ("IdentityService", "DeleteIdentity") => delete_identity(state, request),
        // CarrierService (task F2): the registry-backed read surface plus
        // Listen are real; the instance lifecycle (Create/Update/Start/
        // Stop/DeleteCarrierInstance), Dial, and CloseLink are documented
        // `Unimplemented` — the daemon wires one static carrier set at
        // boot and has no outbound initiator or per-link close path yet.
        ("CarrierService", "ListCarrierTypes") => list_carrier_types(state, request),
        ("CarrierService", "ListLinks") => list_links(state, request),
        ("CarrierService", "GetLinkProperties") => get_link_properties(state, request),
        ("CarrierService", "GetLinkStats") => get_link_stats(state, request),
        ("CarrierService", "Listen") => listen(state, request),
        // ApplicationService (task F4): the registry-backed surface
        // (RegisterApplication/UnregisterApplication/OpenListener) is real;
        // the data plane (sessions, streams, datagrams) has no v1 backing,
        // so each of those methods is Unimplemented with an explicit reason
        // (no server-side dial initiator, no pending-session queue, no
        // per-app stream/datagram handles, no bound-session model).
        ("ApplicationService", "RegisterApplication") => register_application(state, request),
        ("ApplicationService", "UnregisterApplication") => unregister_application(state, request),
        ("ApplicationService", "OpenListener") => open_listener(state, request),
        ("ApplicationService", "CloseListener") => {
            return application_unimplemented(
                request,
                "close-listener: v1 listeners are the app registration; no closeable listener object exists",
            );
        }
        ("ApplicationService", "Connect") => {
            return application_unimplemented(
                request,
                "connect: the node has no server-side dial initiator (v1)",
            );
        }
        ("ApplicationService", "AcceptIncomingSession") => {
            return application_unimplemented(
                request,
                "accept-incoming-session: no pending-session queue on the control surface (v1)",
            );
        }
        ("ApplicationService", "RejectIncomingSession") => {
            return application_unimplemented(
                request,
                "reject-incoming-session: no pending-session queue on the control surface (v1)",
            );
        }
        ("ApplicationService", "OpenStream") => {
            return application_unimplemented(
                request,
                "open-stream: no per-application stream handles (v1)",
            );
        }
        ("ApplicationService", "AcceptStream") => {
            return application_unimplemented(
                request,
                "accept-stream: no pending-stream queue on the control surface (v1)",
            );
        }
        ("ApplicationService", "RejectStream") => {
            return application_unimplemented(
                request,
                "reject-stream: no pending-stream queue on the control surface (v1)",
            );
        }
        ("ApplicationService", "ReadStream") => {
            return application_unimplemented(
                request,
                "read-stream: no per-application stream handles (v1)",
            );
        }
        ("ApplicationService", "WriteStream") => {
            return application_unimplemented(
                request,
                "write-stream: no bound-session model (RegisterApplication carries no session id in v1)",
            );
        }
        ("ApplicationService", "CloseStreamSend") => {
            return application_unimplemented(
                request,
                "close-stream-send: no per-application stream handles (v1)",
            );
        }
        ("ApplicationService", "ResetStream") => {
            return application_unimplemented(
                request,
                "reset-stream: no per-application stream handles (v1)",
            );
        }
        ("ApplicationService", "StopStream") => {
            return application_unimplemented(
                request,
                "stop-stream: no per-application stream handles (v1)",
            );
        }
        ("ApplicationService", "SendDatagram") => {
            return application_unimplemented(
                request,
                "send-datagram: no bound-session model (RegisterApplication carries no session id in v1)",
            );
        }
        ("ApplicationService", "ReceiveDatagram") => {
            return application_unimplemented(
                request,
                "receive-datagram: no datagram queues on the control surface (v1)",
            );
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

/// Frame a `Unimplemented` response that carries the reason (task F4): the
/// documented-split methods of `ApplicationService` fail with an explicit
/// message so clients can distinguish a known gap from a protocol typo.
fn application_unimplemented(request: &api::Request, reason: &str) -> Vec<u8> {
    let envelope = api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence: 1,
        body: Some(api::envelope::Body::Response(api::Response {
            request_id: request.request_id,
            status: Some(api::Status {
                code: api::StatusCode::Unimplemented as i32,
                message: reason.to_string(),
                ..Default::default()
            }),
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
        privacy_profile: state
            .config
            .effective_privacy_profile()
            .as_str()
            .to_string(),
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

/// The v1 peer-table endpoint id is the discovery candidate id (8 bytes):
/// `ListPeers` surfaces it, and `GetPeer`/`AddPeerHint`/`RemovePeer` key
/// off it. The 32-byte identity space (what the accept loop verifies and
/// what `BlockPeer`/`SetTrustState` key) is separate in v1 — see
/// [`block_peer`].
fn peer_endpoint_id_to_candidate(endpoint_id: &[u8]) -> Option<u64> {
    <[u8; 8]>::try_from(endpoint_id)
        .ok()
        .map(u64::from_be_bytes)
}

/// One `PeerSummary` from a discovery candidate (discovery.md §6): the
/// v1 peer table is the candidate table, with the candidate id as the
/// provisional endpoint id (the same mapping `ListPeers` uses).
fn peer_summary(candidate: &PeerCandidate) -> api::PeerSummary {
    api::PeerSummary {
        endpoint_id: candidate.candidate_id.to_be_bytes().to_vec(),
        label: candidate.carrier_type.clone(),
        trust_state: api::TrustState::Observed as i32,
        last_seen_unix_ms: i64::try_from(candidate.expires_at.0).unwrap_or(i64::MAX),
        carrier_hint_count: 1,
        ..Default::default()
    }
}

/// One `PeerHint` mirroring a candidate back out (discovery.md §8): the
/// v1 candidate carries exactly one connection hint.
fn peer_hint(candidate: &PeerCandidate) -> api::PeerHint {
    api::PeerHint {
        carrier_type_id: candidate.carrier_type.clone(),
        connection_hint: candidate.connection_hint.clone(),
        expires_at_unix_ms: i64::try_from(candidate.expires_at.0).unwrap_or(i64::MAX),
        source: match candidate.source {
            CandidateSource::Static => "static",
            CandidateSource::LocalDiscovery => "local-discovery",
            CandidateSource::PeerHint => "peer-hint",
            CandidateSource::Invitation => "invitation",
            CandidateSource::Bootstrap => "bootstrap",
            CandidateSource::Application => "application",
            CandidateSource::CarrierNative => "carrier-native",
        }
        .into(),
        do_not_reshare: candidate.sharing_policy == SharingPolicy::DoNotReshare,
    }
}

/// `PeerService.GetPeer`: one candidate entry by id (discovery.md §24.1).
/// Unknown ids are `NotFound`.
fn get_peer(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(get) = api::GetPeerRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(candidate_id) = peer_endpoint_id_to_candidate(&get.endpoint_id) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(candidate) = state.discovery.candidates.get(candidate_id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let response = api::GetPeerResponse {
        peer: Some(peer_summary(candidate)),
        hints: vec![peer_hint(candidate)],
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `PeerService.AddPeerHint`: record or refresh a candidate from an
/// operator-supplied hint (discovery.md §24.1). The hint's sharing flag
/// maps to the candidate's resharing policy; an expired hint is refused.
fn add_peer_hint(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(add) = api::AddPeerHintRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(candidate_id) = peer_endpoint_id_to_candidate(&add.endpoint_id) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(hint) = add.hint else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let now = wall_now();
    let expires_at = u64::try_from(hint.expires_at_unix_ms).unwrap_or(u64::MAX);
    if expires_at <= now.0 {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let candidate = PeerCandidate {
        candidate_id,
        carrier_type: hint.carrier_type_id,
        connection_hint: hint.connection_hint,
        source: CandidateSource::PeerHint,
        created_at: now,
        expires_at: Instant(expires_at),
        sharing_policy: if hint.do_not_reshare {
            SharingPolicy::DoNotReshare
        } else {
            SharingPolicy::ShareGeneral
        },
        authentication: CandidateAuth::Unauthenticated,
        local: false,
    };
    if let Err(e) = state.discovery.record_candidate(candidate, now) {
        log::warn!("[peers] hint rejected, table full: {e:?}");
        return (api::StatusCode::ResourceExhausted as i32, None);
    }
    let stored = state
        .discovery
        .candidates
        .get(candidate_id)
        .expect("recorded candidate");
    let response = api::AddPeerHintResponse {
        peer: Some(peer_summary(stored)),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `PeerService.RemovePeer`: drop a candidate from the table AND its
/// persisted record (storage.md §16.4), so the peer disappears from
/// `ListPeers`/`GetPeer` and does not come back on restart. Unknown ids
/// are `NotFound`. The `expected_revision` precondition is not enforced in
/// v1 (no resource revisions exist yet).
fn remove_peer(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(remove) = api::RemovePeerRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(candidate_id) = peer_endpoint_id_to_candidate(&remove.endpoint_id) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if state.discovery.candidates.get(candidate_id).is_none() {
        return (api::StatusCode::NotFound as i32, None);
    }
    state.discovery.candidates.remove(candidate_id);
    if let Err(e) = state
        .store
        .delete(Namespace::Peer, &candidate_id.to_be_bytes())
    {
        log::error!("[peers] failed to delete persisted candidate {candidate_id}: {e:?}");
    }
    let mut payload = Vec::new();
    Message::encode(&api::RemovePeerResponse {}, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// The effective trust state of `endpoint` in the proto enum's terms. The
/// v1 trust store has five levels; the spec's seven-state set replaces
/// them in Phase G (gap-closure G1), so this mapping is documented coarse.
fn trust_state_code(state: &RuntimeState, endpoint: &[u8]) -> i32 {
    match state.trust_store().effective_trust_state(endpoint) {
        Ok(umc_core::trust::TrustState::Unknown) | Err(_) => api::TrustState::Unknown as i32,
        Ok(umc_core::trust::TrustState::Observed) => api::TrustState::Observed as i32,
        Ok(umc_core::trust::TrustState::Introduced) => api::TrustState::Introduced as i32,
        Ok(umc_core::trust::TrustState::Trusted) => api::TrustState::Trusted as i32,
        Ok(umc_core::trust::TrustState::Restricted) => api::TrustState::Restricted as i32,
        Ok(umc_core::trust::TrustState::Blocked) => api::TrustState::Blocked as i32,
        Ok(umc_core::trust::TrustState::Revoked) => api::TrustState::Revoked as i32,
    }
}

/// One `PeerSummary` for a security operation (`BlockPeer` etc.): the
/// 32-byte identity space, with the trust state reflecting the blocklist /
/// trust-store reality.
fn security_peer_summary(endpoint_id: &[u8; 32], trust_state: i32) -> api::PeerSummary {
    api::PeerSummary {
        endpoint_id: endpoint_id.to_vec(),
        trust_state,
        ..Default::default()
    }
}

/// The v1 trust-level mapping for `SetTrustState` (identity-trust.md §13):
/// The control API's seven states are persisted without collapsing
/// `Introduced`, `Restricted`, or `Revoked` into the legacy compatibility
/// levels (identity-trust.md §14–15).
fn trust_state_from_proto(state: api::TrustState) -> TrustState {
    match state {
        api::TrustState::Observed => TrustState::Observed,
        api::TrustState::Introduced => TrustState::Introduced,
        api::TrustState::Trusted => TrustState::Trusted,
        api::TrustState::Restricted => TrustState::Restricted,
        api::TrustState::Blocked => TrustState::Blocked,
        api::TrustState::Revoked => TrustState::Revoked,
        api::TrustState::Unknown | api::TrustState::Unspecified => TrustState::Unknown,
    }
}

/// `PeerService.SetTrustState`: move one endpoint's persisted trust level
/// (identity-trust.md §13, security-operations.md §16.3). `UNKNOWN`
/// restores the default; the negative states mark distrusted. Emits a
/// `trust_state_set` event. The `expected_revision` precondition is not
/// enforced in v1 (no resource revisions exist yet).
fn set_trust_state(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(set) = api::SetTrustStateRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(endpoint) = <[u8; 32]>::try_from(set.endpoint_id.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(proto_state) = api::TrustState::try_from(set.trust_state).ok() else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if proto_state == api::TrustState::Unspecified {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let now_ms = wall_now().0;
    let trust_state = trust_state_from_proto(proto_state);
    let trust = state.trust_store();
    let result = match trust_state {
        TrustState::Unknown => trust.remove_distrust(&endpoint),
        other => trust.set_state(&endpoint, other, now_ms),
    };
    if let Err(e) = result {
        log::error!("[peers] trust update failed: {e:?}");
        return (api::StatusCode::Internal as i32, None);
    }
    push_event(
        state,
        "trust_state_set",
        format!(
            "peer {:02x?} -> {proto_state:?} ({trust_state:?}); reason {}",
            endpoint, set.reason
        ),
    );
    let response = api::SetTrustStateResponse {
        peer: Some(security_peer_summary(&endpoint, proto_state as i32)),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `PeerService.BlockPeer` (security-operations.md §16.2): block the
/// 32-byte endpoint identity for the configured blocklist permanence. The
/// accept loop consults the blocklist before registering any session, so
/// the block refuses future sessions. The request's custom
/// `expires_at_unix_ms` is not applied in v1 — the blocklist applies its
/// configured permanence uniformly (custom expiry lands with the blocklist
/// rewrite).
fn block_peer(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(block) = api::BlockPeerRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(endpoint) = <[u8; 32]>::try_from(block.endpoint_id.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    // The blocklist is checked with the node's MONOTONIC clock at admission
    // (the accept loop's now); stamping with wall-clock epoch would make
    // blocks never expire (monotonic < epoch always). In-memory state needs
    // no epoch domain.
    let now = state.node.clock.as_ref().now();
    state.blocklist.block(&endpoint, BlockReason::Operator, now);
    push_event(
        state,
        "peer_blocked",
        format!("peer {:02x?}; reason {}", endpoint, block.reason),
    );
    let response = api::BlockPeerResponse {
        peer: Some(security_peer_summary(
            &endpoint,
            api::TrustState::Blocked as i32,
        )),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `PeerService.UnblockPeer`: lift an active block (security-operations.md
/// §16.2); the response carries the peer's effective trust state, which
/// may still be negative if `SetTrustState` separately marked it
/// distrusted.
fn unblock_peer(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(unblock) = api::UnblockPeerRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(endpoint) = <[u8; 32]>::try_from(unblock.endpoint_id.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    state.blocklist.unblock(&endpoint);
    push_event(state, "peer_unblocked", format!("peer {endpoint:02x?}"));
    let response = api::UnblockPeerResponse {
        peer: Some(security_peer_summary(
            &endpoint,
            trust_state_code(state, &endpoint),
        )),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `PeerService.CreateInvitation` (discovery.md §14, §24.1): issue one
/// invitation whose document embeds the invitation id and the
/// proto-encoded `InvitationScope` (see [`InvitationDocument`]). The
/// issuing identity handle must resolve to the primary or a secondary
/// (task F2); v1 invitations carry no identity binding beyond that
/// selection. `maximum_uses` of exactly 1 makes the invitation single-use;
/// anything else is multi-use in v1 (the store models single-use only).
fn create_invitation(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(create) = api::CreateInvitationRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if let Some(handle) = &create.identity_handle {
        if state.identity_by_handle(&handle.value).is_none() {
            return (api::StatusCode::NotFound as i32, None);
        }
    }
    let Some(scope) = create.scope else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let expires_at_ms = u64::try_from(scope.expires_at_unix_ms).unwrap_or(0);
    if expires_at_ms == 0 {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let single_use = scope.maximum_uses == 1;
    match state
        .invitations
        .create(expires_at_ms, single_use, &OsEntropy)
    {
        Ok(invitation) => {
            let document = InvitationDocument {
                invitation_id: invitation.id.to_vec(),
                scope: Some(scope),
            };
            let mut invitation_document = Vec::new();
            Message::encode(&document, &mut invitation_document).expect("encode");
            push_event(
                state,
                "invitation_created",
                format!(
                    "invitation {:02x?} single_use {single_use} expires {}",
                    invitation.id, expires_at_ms
                ),
            );
            let response = api::CreateInvitationResponse {
                invitation_id: invitation.id.to_vec(),
                invitation_secret: invitation.key.to_vec(),
                invitation_document,
            };
            let mut payload = Vec::new();
            Message::encode(&response, &mut payload).expect("encode");
            (api::StatusCode::Ok as i32, Some(payload))
        }
        Err(InvitationError::Full) => (api::StatusCode::ResourceExhausted as i32, None),
        Err(_) => (api::StatusCode::Internal as i32, None),
    }
}

/// `PeerService.ImportInvitation` (discovery.md §24.1): validate the
/// invitation's id + secret against the store, then record each invited
/// endpoint as a candidate — invitation-authenticated and private, never
/// reshared. The v1 candidate table keys by 8-byte ids, so the first 8
/// bytes of each invited endpoint id key the candidate (documented
/// provisional; endpoints too short to key the table are skipped).
fn import_invitation(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(import) = api::ImportInvitationRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(document) = InvitationDocument::decode(import.invitation_document.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(invitation_id) = <[u8; 16]>::try_from(document.invitation_id.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(scope) = document.scope else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let now = wall_now();
    match state
        .invitations
        .validate(&invitation_id, &import.invitation_secret, now.0)
    {
        Ok(()) => {}
        Err(InvitationError::Unknown) => return (api::StatusCode::NotFound as i32, None),
        Err(_) => {
            return (api::StatusCode::FailedPrecondition as i32, None);
        }
    }
    let candidate_expiry = if scope.expires_at_unix_ms > 0 {
        u64::try_from(scope.expires_at_unix_ms).unwrap_or(u64::MAX)
    } else {
        // No scope expiry: candidates live out the v1 default hint lifetime
        // of 24 hours (discovery.md §8).
        now.0.saturating_add(24 * 60 * 60 * 1_000)
    };
    for endpoint_id in &scope.endpoint_ids {
        let Some(candidate_id) = peer_endpoint_id_to_candidate(endpoint_id) else {
            continue;
        };
        let candidate = PeerCandidate {
            candidate_id,
            carrier_type: scope
                .protocol_ids
                .first()
                .cloned()
                .unwrap_or_else(|| "invitation".into()),
            connection_hint: Vec::new(),
            source: CandidateSource::Invitation,
            created_at: now,
            expires_at: Instant(candidate_expiry),
            sharing_policy: SharingPolicy::LocalUseOnly,
            authentication: CandidateAuth::InvitationAuthenticated,
            local: false,
        };
        if let Err(e) = state.discovery.record_candidate(candidate, now) {
            log::warn!("[peers] imported candidate {candidate_id} rejected: {e:?}");
        }
    }
    push_event(
        state,
        "invitation_imported",
        format!(
            "invitation {:02x?} recorded {} endpoint(s)",
            invitation_id,
            scope.endpoint_ids.len()
        ),
    );
    let response = api::ImportInvitationResponse {
        invitation_id: invitation_id.to_vec(),
        scope: Some(scope),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `PeerService.RevokeInvitation`: revoke by id, idempotently — an
/// unknown or already-revoked invitation still succeeds.
fn revoke_invitation(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(revoke) = api::RevokeInvitationRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(invitation_id) = <[u8; 16]>::try_from(revoke.invitation_id.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    state.invitations.revoke(&invitation_id);
    push_event(
        state,
        "invitation_revoked",
        format!(
            "invitation {:02x?}; reason {}",
            invitation_id, revoke.reason
        ),
    );
    let mut payload = Vec::new();
    Message::encode(&api::RevokeInvitationResponse {}, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// Push one daemon event (core.md §15) from the control surface.
fn push_event(state: &RuntimeState, kind: &str, detail: String) {
    state
        .events
        .lock()
        .expect("event log")
        .push(crate::event_log::DaemonEvent {
            kind: kind.to_string(),
            at_ms: wall_now().0,
            detail,
        });
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

/// The 8-byte session id behind an opaque handle.
fn session_id_from_handle(handle: Option<&api::OpaqueHandle>) -> Option<u64> {
    handle
        .and_then(|handle| <[u8; 8]>::try_from(handle.value.as_slice()).ok())
        .map(u64::from_be_bytes)
}

/// `SessionService.CloseSession` (core.md §9.5): abort the session task via
/// the registry entry's `AbortHandle`. The v1 registry is append-only, so
/// the entry stays (its task is finished); the task watcher records the
/// final `session_closed` event. Unknown handles are `NotFound`.
fn close_session(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(close) = api::CloseSessionRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(session_id) = session_id_from_handle(close.session_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(entry) = state.sessions.lookup(session_id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    entry.task.abort();
    push_event(
        state,
        "session_close_requested",
        format!(
            "session {session_id} peer {:02x?}; code {}; reason {}",
            entry.peer_endpoint_id, close.application_error_code, close.reason
        ),
    );
    let mut payload = Vec::new();
    Message::encode(&api::CloseSessionResponse {}, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `SessionService.ListStreams` (core.md §9.5): the session's open streams.
/// SANCTIONED minimal (gap-closure F3): the v1 registry tracks no open
/// streams — the session object (with its stream table) lives inside the
/// session task, unreachable from the control surface. A known handle
/// returns an empty listing; stream enumeration lands with a shared
/// session handle. Unknown handles are `NotFound`.
fn list_streams(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListStreamsRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(session_id) = session_id_from_handle(list.session_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if state.sessions.lookup(session_id).is_none() {
        return (api::StatusCode::NotFound as i32, None);
    }
    let mut payload = Vec::new();
    Message::encode(&api::ListStreamsResponse::default(), &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
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

fn route_scope_code(scope: RouteScope) -> i32 {
    match scope {
        RouteScope::LinkLocal => api::RouteScope::LinkLocal as i32,
        RouteScope::LocalMesh => api::RouteScope::LocalMesh as i32,
        RouteScope::Introduced => api::RouteScope::Introduced as i32,
        RouteScope::General => api::RouteScope::General as i32,
    }
}

fn route_state_str(state: RouteState) -> &'static str {
    match state {
        RouteState::Candidate => "candidate",
        RouteState::Probing => "probing",
        RouteState::Usable => "usable",
        RouteState::Degraded => "degraded",
        RouteState::Failed => "failed",
        _ => "unknown",
    }
}

/// One `RouteSummary` from a cached route record (routing.md §24): the key
/// hash doubles as the opaque handle, the next hop rides in
/// `carrier_class` (the same field `ListRoutes` uses).
fn route_summary(record: &umc_routing::types::RouteRecord) -> api::RouteSummary {
    api::RouteSummary {
        route_handle: Some(api::OpaqueHandle {
            value: record.key.destination_hash.to_vec(),
        }),
        destination_hint_hash: record.key.destination_hash.to_vec(),
        scope: route_scope_code(record.scope),
        state: route_state_str(record.state).into(),
        hop_count: 1,
        carrier_class: record.next_hop.clone(),
        expires_at_unix_ms: i64::try_from(record.expires_at.0).unwrap_or(i64::MAX),
        last_success_unix_ms: record
            .last_success
            .map_or(0, |instant| i64::try_from(instant.0).unwrap_or(i64::MAX)),
        ..Default::default()
    }
}

/// `RouteService.GetRoute`: one route by handle (the 32-byte destination
/// key hash, matching `ListRoutes`). The cache is consulted first; routes
/// restored from the store but not yet revalidated live only in the
/// persisted snapshot (storage.md §15.2), so the store is the fallback.
/// Unknown hashes are `NotFound`.
fn get_route(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(get) = api::GetRouteRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(hash) = get
        .route_handle
        .as_ref()
        .and_then(|handle| <[u8; 32]>::try_from(handle.value.as_slice()).ok())
    else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    // The route cache is stamped with the node clock (monotonic, per-boot),
    // so cache lookups must compare against the same clock family — the
    // epoch-relative `wall_now()` would see every record as expired.
    let now = state.node.clock.as_ref().now();
    let key = RouteKey {
        destination_profile: 0,
        destination_hash: hash,
        scope: RouteScope::General,
        policy_class: 0,
    };
    let route = state
        .routing
        .cache
        .candidates(&key, now)
        .into_iter()
        .next()
        .map(|record| route_summary(&record))
        .or_else(|| {
            records::list_routes(state.store.as_ref())
                .ok()
                .and_then(|snapshots| {
                    snapshots
                        .into_iter()
                        .find(|snapshot| snapshot.key_hash == hash)
                })
                .map(|snapshot| api::RouteSummary {
                    route_handle: Some(api::OpaqueHandle {
                        value: snapshot.key_hash.clone(),
                    }),
                    destination_hint_hash: snapshot.key_hash,
                    scope: route_scope_from_u8(snapshot.scope),
                    state: "candidate".into(),
                    carrier_class: String::from_utf8_lossy(&snapshot.next_hop).into_owned(),
                    expires_at_unix_ms: i64::try_from(
                        snapshot.learned_at_ms.saturating_add(snapshot.lifetime_ms),
                    )
                    .unwrap_or(i64::MAX),
                    ..Default::default()
                })
        });
    let Some(route) = route else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let response = api::GetRouteResponse {
        route: Some(route),
        // The v1 cache records no legs; nothing to redact.
        redacted_legs: Vec::new(),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `RouteService.ProbeRoute`. SANCTIONED minimal (gap-closure F3): a cache
/// probe, not a wire probe — the daemon has no session-bus route-request
/// path yet (multi-hop `ROUTE_REQUEST` forwarding is Phase H). The
/// destination hint is hashed exactly like a learned route's
/// (routing.md §17) and the best cached candidates are returned; the
/// operation handle is the key hash, and `wait_for_usable` is accepted but
/// has no effect (the cache holds usable and candidate records alike).
fn probe_route(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(probe) = api::ProbeRouteRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let hash = crate::session_task::hash_destination(&probe.destination_hint);
    let key = RouteKey {
        destination_profile: 0,
        destination_hash: hash,
        scope: RouteScope::General,
        policy_class: 0,
    };
    // Node-clock `now`: the cache is stamped with the monotonic node clock
    // (see `get_route`).
    let now = state.node.clock.as_ref().now();
    let candidates: Vec<api::RouteSummary> = state
        .routing
        .cache
        .candidates(&key, now)
        .into_iter()
        .take(3)
        .map(|record| route_summary(&record))
        .collect();
    let response = api::ProbeRouteResponse {
        operation_handle: Some(api::OpaqueHandle {
            value: hash.to_vec(),
        }),
        candidates,
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `RouteService.InvalidateRoute`: drop every cached entry for the key
/// hash AND the persisted snapshot (storage.md §15.3), so the route does
/// not come back on restart. Unknown hashes are `NotFound`. Emits a
/// `route_invalidated` event.
fn invalidate_route(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(invalidate) = api::InvalidateRouteRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(hash) = invalidate
        .route_handle
        .as_ref()
        .and_then(|handle| <[u8; 32]>::try_from(handle.value.as_slice()).ok())
    else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    // Node-clock `now`: the cache is stamped with the monotonic node clock
    // (see `get_route`).
    let now = state.node.clock.as_ref().now();
    let persisted = match records::list_routes(state.store.as_ref()) {
        Ok(snapshots) => snapshots,
        Err(e) => {
            log::error!("[routing] route listing failed: {e:?}");
            return (api::StatusCode::Internal as i32, None);
        }
    };
    let persisted_hit = persisted.iter().any(|snapshot| snapshot.key_hash == hash);
    let cache_hit = [
        RouteScope::LinkLocal,
        RouteScope::LocalMesh,
        RouteScope::Introduced,
        RouteScope::General,
    ]
    .into_iter()
    .any(|scope| {
        let key = RouteKey {
            destination_profile: 0,
            destination_hash: hash,
            scope,
            policy_class: 0,
        };
        !state.routing.cache.candidates(&key, now).is_empty()
    });
    if !persisted_hit && !cache_hit {
        return (api::StatusCode::NotFound as i32, None);
    }
    for scope in [
        RouteScope::LinkLocal,
        RouteScope::LocalMesh,
        RouteScope::Introduced,
        RouteScope::General,
    ] {
        let key = RouteKey {
            destination_profile: 0,
            destination_hash: hash,
            scope,
            policy_class: 0,
        };
        state.routing.cache.remove(&key);
    }
    if let Err(e) = state.store.delete(Namespace::Route, &hash) {
        log::error!("[routing] failed to delete persisted route: {e:?}");
        return (api::StatusCode::Internal as i32, None);
    }
    push_event(
        state,
        "route_invalidated",
        format!("hash {hash:02x?}; reason {}", invalidate.reason),
    );
    let mut payload = Vec::new();
    Message::encode(&api::InvalidateRouteResponse {}, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
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
            key: "privacy_profile".into(),
            value: config.effective_privacy_profile().as_str().into(),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "privacy_policy_override".into(),
            value: config.privacy_policy_override.clone().unwrap_or_default(),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "public_relay".into(),
            value: config.public_relay.to_string(),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "disable_public_relay".into(),
            value: config.disable_public_relay.to_string(),
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
        api::ConfigEntry {
            key: "tls_listen".into(),
            value: config.tls_listen.clone().unwrap_or_default(),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "disabled_protocol_versions".into(),
            value: config.disabled_protocol_versions.join(","),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "disabled_crypto_profiles".into(),
            value: config.disabled_crypto_profiles.join(","),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "disabled_carriers".into(),
            value: config.disabled_carriers.join(","),
            sensitive_present: false,
        },
        api::ConfigEntry {
            key: "static_peers".into(),
            value: serde_json::to_string(&config.static_peers).unwrap_or_else(|_| "[]".into()),
            sensitive_present: false,
        },
    ];
    api::NodeConfig {
        resource_profile: config.profile.clone(),
        telemetry_enabled: config.telemetry_enabled,
        public_relay_enabled: config.public_relay && !config.disable_public_relay,
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

/// `BundleService.CreateBundle`: seal a payload when the destination hint is a
/// static handshake public key, then admit the opaque envelope. Legacy hints
/// that are not 32-byte keys retain the experimental opaque-payload behavior;
/// this keeps v0.1 callers interoperable while making the destination-bound
/// path available without adding a new control message field.
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
    let stored_payload = seal_bundle_for_hint(&create.payload_chunk, &create.destination_hint);
    match state.bundle.admit(
        &stored_payload,
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
                        encrypted_payload: stored_payload.clone(),
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

fn seal_bundle_for_hint(payload: &[u8], destination_hint: &[u8]) -> Vec<u8> {
    let Ok(destination_key) = <[u8; 32]>::try_from(destination_hint) else {
        return payload.to_vec();
    };
    let sender_ephemeral = umc_crypto::signatures::StaticHandshakeKeyPair::generate();
    let envelope = seal_bundle(
        &sender_ephemeral,
        &umc_crypto::signatures::StaticHandshakePublicKey(destination_key),
        payload,
    );
    envelope.encode()
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
    if state.config.disable_public_relay && !open.private_handling {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
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

// --- Task F4: RelayService remaining methods ---

/// `RelayService.GetRelayStatus`: the v1 `AdmissionLimits` mapped onto the
/// proto policy, plus live circuit counts. `queued_bytes` is always 0 —
/// the v1 relay has no queue (relay.md §8-24).
fn get_relay_status(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let _ = request;
    let snapshot = state.relay.snapshot();
    let opening_circuits = snapshot
        .iter()
        .filter(|snap| {
            matches!(
                snap.circuit.state,
                umc_relay::circuit::CircuitState::Opening
            )
        })
        .count();
    let bytes_forwarded: u64 = snapshot
        .iter()
        .map(|snap| snap.circuit.bytes_forwarded)
        .sum();
    let status = api::RelayStatus {
        policy: Some(relay_policy_message(&state.relay.limits)),
        opening_circuits: u32::try_from(opening_circuits).unwrap_or(u32::MAX),
        active_circuits: u32::try_from(state.relay.circuit_count()).unwrap_or(u32::MAX),
        queued_bytes: 0,
        bytes_forwarded,
        pressure: api::ResourcePressure::Normal as i32,
    };
    let response = api::GetRelayStatusResponse {
        status: Some(status),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// The v1 `AdmissionLimits` as the proto `RelayPolicy` (task F4). The
/// v1 limits model mode, the per-peer cap, the per-circuit byte quota, and
/// the lifetime cap; idle timeout, bandwidth, and the trust/carrier/route
/// allowlists are not modeled (they ride as defaults).
fn relay_policy_message(limits: &umc_relay::admission::AdmissionLimits) -> api::RelayPolicy {
    api::RelayPolicy {
        mode: match limits.policy {
            umc_relay::admission::RelayPolicy::Disabled => api::RelayMode::Disabled as i32,
            umc_relay::admission::RelayPolicy::FriendsOnly => api::RelayMode::FriendsOnly as i32,
            umc_relay::admission::RelayPolicy::Community => api::RelayMode::Community as i32,
            umc_relay::admission::RelayPolicy::Public => api::RelayMode::Public as i32,
        },
        maximum_circuits_per_peer: u32::try_from(limits.max_circuits_per_peer).unwrap_or(u32::MAX),
        maximum_bytes_per_circuit: limits.max_byte_quota,
        maximum_lifetime_ms: limits.max_lifetime_ms,
        ..Default::default()
    }
}

/// `RelayService.UpdateRelayPolicy` (control-api.md §30.1): mutate the
/// in-memory `AdmissionLimits`. `expected_revision` is not enforced (no
/// resource revisions exist yet); `maximum_circuits`, `maximum_idle_ms`,
/// `maximum_bytes_per_second`, and the allowlists are not modeled by the
/// v1 limits and are ignored (documented). Zero-valued fields mean "no
/// change" for the modeled limits.
fn update_relay_policy(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(update) = api::UpdateRelayPolicyRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(policy) = update.policy else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(mode) = api::RelayMode::try_from(policy.mode) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if mode == api::RelayMode::Unspecified {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    {
        let limits = &mut state.relay.limits;
        limits.policy = match mode {
            api::RelayMode::Disabled => umc_relay::admission::RelayPolicy::Disabled,
            api::RelayMode::FriendsOnly => umc_relay::admission::RelayPolicy::FriendsOnly,
            api::RelayMode::Community => umc_relay::admission::RelayPolicy::Community,
            api::RelayMode::Public => umc_relay::admission::RelayPolicy::Public,
            api::RelayMode::Unspecified => unreachable!("rejected above"),
        };
        if policy.maximum_circuits_per_peer > 0 {
            limits.max_circuits_per_peer =
                usize::try_from(policy.maximum_circuits_per_peer).unwrap_or(usize::MAX);
        }
        if policy.maximum_bytes_per_circuit > 0 {
            limits.max_byte_quota = policy.maximum_bytes_per_circuit;
        }
        if policy.maximum_lifetime_ms > 0 {
            limits.max_lifetime_ms = policy.maximum_lifetime_ms;
        }
    }
    push_event(
        state,
        "relay_policy_updated",
        format!("policy {:?}", state.relay.limits.policy),
    );
    let response = api::UpdateRelayPolicyResponse {
        policy: Some(relay_policy_message(&state.relay.limits)),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// The v1 redaction for circuit peer identifiers (relay.md §30.2,
/// control-api.md §30.1): keep the first 4 bytes of an endpoint id and
/// zero the rest, so the operator sees identity without the full peer.
fn redact_peer(peer: Option<&[u8]>) -> Vec<u8> {
    let Some(peer) = peer else {
        return Vec::new();
    };
    let mut out = peer.to_vec();
    for byte in out.iter_mut().skip(4) {
        *byte = 0;
    }
    out
}

/// The circuit state as the proto's lowercase string (`"opening"`,
/// `"active"`, `"closing"`, ...).
fn circuit_state_name(state: umc_relay::circuit::CircuitState) -> String {
    format!("{state:?}").to_ascii_lowercase()
}

/// `RelayService.ListRelayCircuits` (control-api.md §30.1): a snapshot of
/// every circuit with redacted owner/destination peers, paginated
/// (control-api.md §37). The circuit handle is the 8-byte BE circuit id —
/// the same value `OpenCircuit` returns. The optional `state` filter keeps
/// only circuits whose v1 state matches.
fn list_relay_circuits(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListRelayCircuitsRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok((offset, page_size)) = page_window(list.page.as_ref(), "ListRelayCircuits") else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let all: Vec<_> = state
        .relay
        .snapshot()
        .into_iter()
        .filter(|snap| {
            list.state.is_empty() || circuit_state_name(snap.circuit.state) == list.state
        })
        .collect();
    let total = all.len();
    let circuits = all
        .into_iter()
        .skip(offset)
        .take(page_size)
        .map(|snap| api::RelayCircuitSummary {
            circuit_handle: Some(api::OpaqueHandle {
                value: snap.circuit_id.to_be_bytes().to_vec(),
            }),
            state: circuit_state_name(snap.circuit.state),
            redacted_upstream_peer: redact_peer(snap.owner_peer.as_deref()),
            redacted_downstream_peer: redact_peer(snap.destination.as_deref()),
            granted_byte_quota: snap.circuit.granted_byte_quota,
            accepted_bytes: snap.circuit.bytes_forwarded,
            expires_at_unix_ms: i64::try_from(snap.circuit.expires_at.0).unwrap_or(i64::MAX),
            last_activity_unix_ms: i64::try_from(snap.circuit.last_activity.0).unwrap_or(i64::MAX),
            private_circuit: snap.circuit.private_handling,
        })
        .collect();
    let response = api::ListRelayCircuitsResponse {
        circuits,
        page: Some(page_info(total, offset, page_size, "ListRelayCircuits")),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `RelayService.CloseRelayCircuit` (control-api.md §30.1): close by the
/// circuit handle — the 8-byte BE circuit id `OpenCircuit`/`ListRelayCircuits`
/// carry. The string reason rides into the event log; the v1 close path
/// applies `NoError` (the relay reason codes are wire-only for now).
fn close_relay_circuit(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(close) = api::CloseRelayCircuitRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(circuit_id) = close
        .circuit_handle
        .as_ref()
        .and_then(|handle| <[u8; 8]>::try_from(handle.value.as_slice()).ok())
        .map(u64::from_be_bytes)
    else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let now = state.node.clock.as_ref().now();
    match state.relay.close_circuit(circuit_id, 0, now) {
        Ok(()) => {
            state.metrics.incr(metric_names::RELAY_CIRCUITS_CLOSED, 1);
            push_event(
                state,
                "relay_circuit_closed",
                format!("circuit {circuit_id}; reason {}", close.reason),
            );
            let mut payload = Vec::new();
            Message::encode(&api::CloseRelayCircuitResponse {}, &mut payload).expect("encode");
            (api::StatusCode::Ok as i32, Some(payload))
        }
        Err(_) => (api::StatusCode::NotFound as i32, None),
    }
}

// --- Task F4: BundleService remaining methods ---

/// `BundleService.GetBundle` (control-api.md §30.2): the record summary
/// plus an optional payload chunk. Chunking honors `payload_offset` /
/// `payload_length` (0 length means "to the end"); `payload_eof` marks the
/// final chunk. The v1 `BundleSummary` carries the raw destination hint in
/// `destination_hint_hash` (the hint-hash plumbing lands with bundle
/// routing). Unknown ids are `NotFound`.
fn get_bundle(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(get) = api::GetBundleRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(id) = <[u8; 32]>::try_from(get.bundle_id.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(record) = state.bundle.record(&id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let size = record.size;
    let (payload_chunk, payload_eof) = if get.include_payload {
        let payload = state.bundle.payload(&id).unwrap_or_default();
        let offset = usize::try_from(get.payload_offset)
            .unwrap_or(usize::MAX)
            .min(payload.len());
        let length = if get.payload_length == 0 {
            payload.len().saturating_sub(offset)
        } else {
            usize::try_from(get.payload_length)
                .unwrap_or(usize::MAX)
                .min(payload.len().saturating_sub(offset))
        };
        let end = offset.saturating_add(length);
        (payload[offset..end].to_vec(), end >= size)
    } else {
        (Vec::new(), false)
    };
    let response = api::GetBundleResponse {
        bundle: Some(api::BundleSummary {
            bundle_id: id.to_vec(),
            owner_endpoint_id: record.sender.clone(),
            destination_hint_hash: record.destination_hint.clone(),
            state: bundle_state(&record.status) as i32,
            payload_size: u64::try_from(size).unwrap_or(u64::MAX),
            priority: u32::try_from(record.priority).unwrap_or(u32::MAX),
            created_at_unix_ms: i64::try_from(record.created_at.0).unwrap_or(i64::MAX),
            expires_at_unix_ms: i64::try_from(record.expires_at.0).unwrap_or(i64::MAX),
        }),
        payload_chunk,
        payload_eof,
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `BundleService.DeleteBundle` (control-api.md §30.2): remove the record
/// via the manager — which releases the quota reservation, the sender
/// count, and the persisted metadata (bundles.md §11). The content-
/// addressed object payload stays behind: shared objects are refcounted by
/// the eviction path, so a delete only drops the record. Unknown ids are
/// `NotFound`.
fn delete_bundle(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(delete) = api::DeleteBundleRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(id) = <[u8; 32]>::try_from(delete.bundle_id.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if state.bundle.record(&id).is_none() {
        return (api::StatusCode::NotFound as i32, None);
    }
    state.bundle.manager.remove(&id);
    push_event(
        state,
        "bundle_deleted",
        format!("bundle {id:02x?}; reason {}", delete.reason),
    );
    let mut payload = Vec::new();
    Message::encode(&api::DeleteBundleResponse {}, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

// --- Task F4: ApplicationService (registry-backed surface) ---

/// `ApplicationService.RegisterApplication` (control-api.md §31): register
/// every requested protocol id with the `AppRegistry` (service name =
/// `application_name`) and create the app's inbound stream channel — the
/// same wiring `install_echo_app` uses, so session tasks can forward
/// inbound stream data to the app. The v1 application handle is the first
/// registered protocol id (documented deviation from the spec's 16-byte
/// opaque handles). A failed multi-protocol registration rolls back the
/// already-registered ids. Channel consumers (the application-side drain
/// tasks) land with in-process app hosting.
fn register_application(
    state: &mut RuntimeState,
    request: &api::Request,
) -> (i32, Option<Vec<u8>>) {
    let Ok(register) = api::RegisterApplicationRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if register.application_name.is_empty() || register.requested_protocol_ids.is_empty() {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let mut registered_protocols = Vec::with_capacity(register.requested_protocol_ids.len());
    for protocol_id in &register.requested_protocol_ids {
        match state.apps.register(
            protocol_id.as_bytes().to_vec(),
            register.application_name.clone(),
        ) {
            Ok(()) => registered_protocols.push(protocol_id.as_bytes().to_vec()),
            Err(umc_core::app::AppError::AlreadyRegistered) => {
                for earlier in &registered_protocols {
                    let _ = state.apps.unregister(earlier);
                }
                return (api::StatusCode::AlreadyExists as i32, None);
            }
            Err(umc_core::app::AppError::InvalidProtocolId) => {
                for earlier in &registered_protocols {
                    let _ = state.apps.unregister(earlier);
                }
                return (api::StatusCode::InvalidArgument as i32, None);
            }
            Err(umc_core::app::AppError::NotFound) => unreachable!("register never not-finds"),
        }
    }
    let mut channels = state.app_channels.lock().expect("app channels");
    let mut receivers = state.app_echo_rx.lock().expect("app echo receivers");
    for protocol_id in &register.requested_protocol_ids {
        let (in_tx, in_rx) =
            umc_core::app_io::spawn_app_channel(crate::app_layer::APP_CHANNEL_BUFFER);
        channels.insert(protocol_id.as_bytes().to_vec(), in_tx);
        // Keep the receiver alive. The session writer drains this map for
        // in-process application hosting; dropping it here makes every
        // forwarded frame fail with a closed-channel error.
        receivers.insert(protocol_id.as_bytes().to_vec(), in_rx);
    }
    drop(receivers);
    drop(channels);
    state.application_protocols.insert(
        register.requested_protocol_ids[0].as_bytes().to_vec(),
        registered_protocols,
    );
    push_event(
        state,
        "application_registered",
        format!(
            "{} ({} protocol id(s))",
            register.application_name,
            register.requested_protocol_ids.len()
        ),
    );
    let response = api::RegisterApplicationResponse {
        application_handle: Some(api::OpaqueHandle {
            value: register.requested_protocol_ids[0].as_bytes().to_vec(),
        }),
        // v1: no capability-grant or resumable-principal model yet.
        effective_grants: Vec::new(),
        resume_token: Vec::new(),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `ApplicationService.UnregisterApplication` (control-api.md §31): drop
/// the app from the registry and remove every protocol/channel belonging to
/// its handle. Unknown handles are `NotFound`. `close_owned_sessions` is moot
/// in v1: no sessions are owned (no bound-session model).
fn unregister_application(
    state: &mut RuntimeState,
    request: &api::Request,
) -> (i32, Option<Vec<u8>>) {
    let Ok(unregister) = api::UnregisterApplicationRequest::decode(request.payload.as_slice())
    else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = unregister.application_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(protocol_ids) = state
        .application_protocols
        .remove(&handle.value)
        .or_else(|| {
            state
                .apps
                .lookup(&handle.value)
                .map(|_| vec![handle.value.clone()])
        })
    else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let mut channels = state.app_channels.lock().expect("app channels");
    let mut receivers = state.app_echo_rx.lock().expect("app echo receivers");
    for protocol_id in protocol_ids {
        let _ = state.apps.unregister(&protocol_id);
        channels.remove(&protocol_id);
        receivers.remove(&protocol_id);
    }
    drop(receivers);
    drop(channels);
    push_event(state, "application_unregistered", String::new());
    let mut payload = Vec::new();
    Message::encode(&api::UnregisterApplicationResponse {}, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `ApplicationService.OpenListener` (control-api.md §32): bind the app's
/// protocol registration as a listener. The v1 listener IS the registry
/// entry — inbound stream dispatch already routes matching protocol ids to
/// the app's channel — so this validates the registration and returns the
/// protocol id as the listener handle. Unknown apps are `NotFound`; a
/// protocol id the app does not serve is `InvalidArgument`.
fn open_listener(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(open) = api::OpenListenerRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = open.application_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if state.apps.lookup(&handle.value).is_none() {
        return (api::StatusCode::NotFound as i32, None);
    }
    if !open.protocol_id.is_empty() && open.protocol_id.as_bytes() != handle.value.as_slice() {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let response = api::OpenListenerResponse {
        listener_handle: Some(api::OpaqueHandle {
            value: handle.value,
        }),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

// --- Task F2: IdentityService (all nine proto RPCs) ---

/// One `IdentitySummary` from a registry entry (task F2): the record name
/// is the identity handle; the binding sequence doubles as the revision.
fn identity_summary(
    record_name: &str,
    endpoint_id: [u8; 32],
    binding: &umc_handshake::identity::IdentityBinding,
    kind: i32,
    label: &str,
) -> api::IdentitySummary {
    api::IdentitySummary {
        identity_handle: Some(api::OpaqueHandle {
            value: record_name.as_bytes().to_vec(),
        }),
        endpoint_id: endpoint_id.to_vec(),
        kind,
        label: label.to_string(),
        binding_sequence: binding.sequence,
        binding_not_after_unix_ms: i64::try_from(binding.not_after).unwrap_or(i64::MAX),
        secret_available: true,
        revision: Some(api::ResourceRevision {
            value: binding.sequence,
        }),
    }
}

/// The primary identity's summary: handle `node-identity`, kind
/// `NODE_MANAGEMENT`.
fn primary_summary(state: &RuntimeState) -> api::IdentitySummary {
    identity_summary(
        &String::from_utf8_lossy(NODE_IDENTITY_RECORD),
        state.node_identity.endpoint_id(),
        &state.primary_binding,
        api::IdentityKind::NodeManagement as i32,
        "node",
    )
}

/// The summary for whichever identity `resolved` names.
fn summary_for(state: &RuntimeState, resolved: IdentityRef<'_>) -> api::IdentitySummary {
    match resolved {
        IdentityRef::Primary => primary_summary(state),
        IdentityRef::Secondary(entry) => identity_summary(
            &entry.record_name,
            entry.identity.endpoint_id(),
            &entry.binding,
            entry.kind,
            &entry.label,
        ),
    }
}

/// `IdentityService.ListIdentities`: the primary plus every secondary,
/// paginated (control-api.md §37).
fn list_identities(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListIdentitiesRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok((offset, page_size)) = page_window(list.page.as_ref(), "ListIdentities") else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let mut all = Vec::with_capacity(1 + state.secondaries.len());
    all.push(primary_summary(state));
    all.extend(state.secondaries.iter().map(|entry| {
        identity_summary(
            &entry.record_name,
            entry.identity.endpoint_id(),
            &entry.binding,
            entry.kind,
            &entry.label,
        )
    }));
    let total = all.len();
    let identities = all.into_iter().skip(offset).take(page_size).collect();
    let response = api::ListIdentitiesResponse {
        identities,
        page: Some(page_info(total, offset, page_size, "ListIdentities")),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `IdentityService.GetIdentity`: one identity by handle or endpoint id,
/// with the signed binding as the public material.
fn get_identity(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(get) = api::GetIdentityRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let resolved = match get.identity {
        Some(api::get_identity_request::Identity::Handle(handle)) => {
            state.identity_by_handle(&handle.value)
        }
        Some(api::get_identity_request::Identity::EndpointId(endpoint)) => {
            state.identity_by_endpoint(&endpoint)
        }
        None => return (api::StatusCode::InvalidArgument as i32, None),
    };
    let Some(resolved) = resolved else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let public_binding = match resolved {
        IdentityRef::Primary => state.primary_binding.signed_bytes(),
        IdentityRef::Secondary(entry) => entry.binding.signed_bytes(),
    };
    let response = api::GetIdentityResponse {
        identity: Some(summary_for(state, resolved)),
        public_binding,
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `IdentityService.CreateIdentity`: generate a SECONDARY identity,
/// keystore-stored. The node identity is never touched.
fn create_identity(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(create) = api::CreateIdentityRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if create.kind == api::IdentityKind::Unspecified as i32 {
        // The kind drives the summary; an unspecified kind is a client
        // bug (control-api.md §32).
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let lifetime_ms = u64::try_from(create.binding_lifetime_ms).unwrap_or(0);
    match state.create_secondary_identity(create.kind, &create.label, lifetime_ms) {
        Ok(secondary) => {
            let response = api::CreateIdentityResponse {
                identity: Some(identity_summary(
                    &secondary.record_name,
                    secondary.identity.endpoint_id(),
                    &secondary.binding,
                    secondary.kind,
                    &secondary.label,
                )),
                public_binding: secondary.binding.signed_bytes(),
            };
            let mut payload = Vec::new();
            Message::encode(&response, &mut payload).expect("encode");
            (api::StatusCode::Ok as i32, Some(payload))
        }
        Err(e) => {
            log::warn!("[identity] create failed: {e}");
            (api::StatusCode::Internal as i32, None)
        }
    }
}

/// `IdentityService.RotateHandshakeKey`: fresh static handshake key,
/// binding re-signed at sequence + 1, persisted; the node switches to the
/// new static key for future handshakes (handshake.md §33).
fn rotate_handshake_key(
    state: &mut RuntimeState,
    request: &api::Request,
) -> (i32, Option<Vec<u8>>) {
    let Ok(rotate) = api::RotateHandshakeKeyRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = rotate.identity_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(resolved) = state.identity_by_handle(&handle.value) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if let Some(expected) = rotate.expected_revision {
        let current = match resolved {
            IdentityRef::Primary => state.primary_binding.sequence,
            IdentityRef::Secondary(entry) => entry.binding.sequence,
        };
        if expected.value != current {
            return (api::StatusCode::Conflict as i32, None);
        }
    }
    let lifetime_ms = u64::try_from(rotate.new_binding_lifetime_ms).unwrap_or(0);
    match state.rotate_handshake_key(&handle.value, lifetime_ms) {
        Ok(binding) => {
            let summary = match state.identity_by_handle(&handle.value) {
                Some(resolved) => summary_for(state, resolved),
                None => return (api::StatusCode::NotFound as i32, None),
            };
            let response = api::RotateHandshakeKeyResponse {
                identity: Some(summary),
                public_binding: binding.signed_bytes(),
            };
            let mut payload = Vec::new();
            Message::encode(&response, &mut payload).expect("encode");
            (api::StatusCode::Ok as i32, Some(payload))
        }
        Err(e) => {
            log::warn!("[identity] rotate handshake key failed: {e}");
            (api::StatusCode::Internal as i32, None)
        }
    }
}

/// `IdentityService.RotateIdentityKey`: a full identity change — fresh
/// identity and static keys, new endpoint id, persisted. The primary's
/// session-ticket key follows the new identity, so existing tickets stop
/// being redeemable (documented; it is a NEW endpoint).
fn rotate_identity_key(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(rotate) = api::RotateIdentityKeyRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = rotate.identity_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if rotate.require_old_key_signature {
        // The request carries no old-signature material to verify against;
        // the flag is unsupported (documented).
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let Some(resolved) = state.identity_by_handle(&handle.value) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if let Some(expected) = rotate.expected_revision {
        let current = match resolved {
            IdentityRef::Primary => state.primary_binding.sequence,
            IdentityRef::Secondary(entry) => entry.binding.sequence,
        };
        if expected.value != current {
            return (api::StatusCode::Conflict as i32, None);
        }
    }
    match state.rotate_identity_key(&handle.value) {
        Ok(binding) => {
            let summary = match state.identity_by_handle(&handle.value) {
                Some(resolved) => summary_for(state, resolved),
                None => return (api::StatusCode::NotFound as i32, None),
            };
            let response = api::RotateIdentityKeyResponse {
                identity: Some(summary),
                rotation_proof: binding.signature.to_vec(),
            };
            let mut payload = Vec::new();
            Message::encode(&response, &mut payload).expect("encode");
            (api::StatusCode::Ok as i32, Some(payload))
        }
        Err(e) => {
            log::warn!("[identity] rotate identity key failed: {e}");
            (api::StatusCode::Internal as i32, None)
        }
    }
}

/// `IdentityService.ExportPublicIdentity`: the signed binding (public
/// material only — endpoint id, public keys, validity, sequence,
/// signature).
fn export_public_identity(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(export) = api::ExportPublicIdentityRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = export.identity_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(resolved) = state.identity_by_handle(&handle.value) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let public_binding = match resolved {
        IdentityRef::Primary => state.primary_binding.signed_bytes(),
        IdentityRef::Secondary(entry) => entry.binding.signed_bytes(),
    };
    let response = api::ExportPublicIdentityResponse {
        export_bytes: public_binding,
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `IdentityService.ExportSecretIdentity`: the raw 64-byte
/// `[identity_seed || static_seed]` material. Gated behind the
/// `allow_secret_export` config flag (default off) — without it the
/// request is `PermissionDenied`. The proto names the field
/// `encrypted_export`; v1 exports the raw seeds in it (no wrapping
/// envelope yet, documented), and the `protection`/`confirmation` request
/// fields are accepted but ignored.
fn export_secret_identity(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    if !state.config.allow_secret_export {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    let Ok(export) = api::ExportSecretIdentityRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = export.identity_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(resolved) = state.identity_by_handle(&handle.value) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let identity = match resolved {
        IdentityRef::Primary => &state.node_identity,
        IdentityRef::Secondary(entry) => &entry.identity,
    };
    let mut seeds = Vec::with_capacity(64);
    seeds.extend_from_slice(&identity.identity.to_seed());
    seeds.extend_from_slice(&identity.static_handshake.to_seed());
    let response = api::ExportSecretIdentityResponse {
        encrypted_export: seeds,
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `IdentityService.ImportIdentity`: the `encrypted_export` field carries
/// raw 64-byte seeds (mirroring the v1 export); the seeds are keystore-
/// stored as a NEW secondary. The primary can never be replaced via
/// import. `validate_only` reports the would-be identity without storing.
fn import_identity(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(import) = api::ImportIdentityRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if import.encrypted_export.len() != 64 {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    match state.import_secondary_identity(
        &import.encrypted_export,
        "imported",
        import.validate_only,
    ) {
        Ok(secondary) => {
            let response = api::ImportIdentityResponse {
                identity: Some(identity_summary(
                    &secondary.record_name,
                    secondary.identity.endpoint_id(),
                    &secondary.binding,
                    secondary.kind,
                    &secondary.label,
                )),
            };
            let mut payload = Vec::new();
            Message::encode(&response, &mut payload).expect("encode");
            (api::StatusCode::Ok as i32, Some(payload))
        }
        Err(e) => {
            log::warn!("[identity] import failed: {e}");
            (api::StatusCode::Internal as i32, None)
        }
    }
}

/// `IdentityService.DeleteIdentity`: deletes a SECONDARY identity from the
/// registry and keystore. The primary is `FailedPrecondition` — a full
/// replacement is `RotateIdentityKey`. `plan_only` reports the would-be
/// deletion without executing; the deletion-plan token is accepted but
/// ignored (no dependency planning in v1).
fn delete_identity(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(delete) = api::DeleteIdentityRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = delete.identity_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(resolved) = state.identity_by_handle(&handle.value) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if let IdentityRef::Primary = resolved {
        return (api::StatusCode::FailedPrecondition as i32, None);
    }
    if let Some(expected) = delete.expected_revision {
        if let IdentityRef::Secondary(entry) = resolved {
            if expected.value != entry.binding.sequence {
                return (api::StatusCode::Conflict as i32, None);
            }
        }
    }
    if delete.plan_only {
        let response = api::DeleteIdentityResponse {
            deleted: false,
            deletion_plan_token: Vec::new(),
            dependencies: Vec::new(),
        };
        let mut payload = Vec::new();
        Message::encode(&response, &mut payload).expect("encode");
        return (api::StatusCode::Ok as i32, Some(payload));
    }
    match state.delete_secondary_identity(&handle.value) {
        Ok(()) => {
            let response = api::DeleteIdentityResponse {
                deleted: true,
                deletion_plan_token: Vec::new(),
                dependencies: Vec::new(),
            };
            let mut payload = Vec::new();
            Message::encode(&response, &mut payload).expect("encode");
            (api::StatusCode::Ok as i32, Some(payload))
        }
        Err(e) => {
            log::warn!("[identity] delete failed: {e}");
            (api::StatusCode::Internal as i32, None)
        }
    }
}

// --- Task F2: CarrierService (registry-backed read surface + Listen) ---

/// The capability report for one registered carrier (task F2).
fn carrier_type_info(carrier: &(dyn Carrier + Send + Sync)) -> api::CarrierTypeInfo {
    let caps = carrier.capabilities();
    api::CarrierTypeInfo {
        type_id: caps.carrier_type.0.clone(),
        display_name: caps.carrier_type.0,
        built_in: true,
        supports_listen: caps.supports_listen,
        supports_dial: caps.supports_dial,
        supports_discovery: caps.supports_discovery,
        minimum_packet_size: u32::try_from(caps.minimum_packet_size).unwrap_or(u32::MAX),
        maximum_packet_size: u32::try_from(caps.maximum_packet_size).unwrap_or(u32::MAX),
    }
}

/// Every registered carrier, in config order (task F2): the daemon wires
/// one carrier per configured type id at boot (carriers.rs), so the
/// registry is enumerated by resolving the configured ids against the
/// runtime node. Configured-but-unregistered ids are skipped.
fn registered_carriers(state: &RuntimeState) -> Vec<api::CarrierTypeInfo> {
    state
        .config
        .carriers
        .iter()
        .filter_map(|type_id| state.node.carrier(type_id).map(carrier_type_info))
        .collect()
}

/// `CarrierService.ListCarrierTypes`: the registered carriers and their
/// capabilities, paginated (control-api.md §37).
fn list_carrier_types(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListCarrierTypesRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok((offset, page_size)) = page_window(list.page.as_ref(), "ListCarrierTypes") else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let all = registered_carriers(state);
    let total = all.len();
    let types = all.into_iter().skip(offset).take(page_size).collect();
    let response = api::ListCarrierTypesResponse {
        types,
        page: Some(page_info(total, offset, page_size, "ListCarrierTypes")),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `CarrierService.ListLinks`: the active session registry as links,
/// paginated (control-api.md §37). The v1 registry does not track MTU or
/// byte counters, so those fields report 0 (documented).
fn list_links(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListLinksRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok((offset, page_size)) = page_window(list.page.as_ref(), "ListLinks") else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let all = state.sessions.snapshot();
    let total = all.len();
    let links = all
        .into_iter()
        .skip(offset)
        .take(page_size)
        .map(|(id, entry)| api::LinkSummary {
            link_handle: Some(api::OpaqueHandle {
                value: id.to_be_bytes().to_vec(),
            }),
            carrier_handle: Some(api::OpaqueHandle {
                value: entry.carrier_type.as_bytes().to_vec(),
            }),
            carrier_type_id: entry.carrier_type.clone(),
            state: "active".into(),
            current_mtu: 0,
            bytes_sent: 0,
            bytes_received: 0,
            scope: "session".into(),
        })
        .collect();
    let response = api::ListLinksResponse {
        links,
        page: Some(page_info(total, offset, page_size, "ListLinks")),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `CarrierService.GetLinkProperties`: the capability report for one
/// carrier type. Unknown types are `NotFound`.
fn get_link_properties(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(get) = GetLinkPropertiesRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(carrier) = state.node.carrier(&get.carrier_type) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let response = GetLinkPropertiesResponse {
        info: Some(carrier_type_info(carrier)),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `CarrierService.GetLinkStats`: the active-session count per registered
/// carrier; carriers without sessions report 0.
fn get_link_stats(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let _ = request;
    let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for info in registered_carriers(state) {
        counts.insert(info.type_id, 0);
    }
    for (_id, entry) in state.sessions.snapshot() {
        *counts.entry(entry.carrier_type.clone()).or_insert(0) += 1;
    }
    let link_stats = counts
        .into_iter()
        .map(|(carrier_type, active_links)| LinkStats {
            carrier_type,
            active_links,
        })
        .collect();
    let response = GetLinkStatsResponse { stats: link_stats };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// `CarrierService.Listen`: bind one registered carrier at an explicit
/// address and hold the listener. The reported `bound_address` is the
/// requested address — the `Listener` trait exposes no kernel-assigned
/// address, so an ephemeral port is not resolved (documented).
fn listen(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(listen) = ListenRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(carrier) = state.node.carrier(&listen.carrier_type) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if state.config.carrier_disabled(&listen.carrier_type) {
        return (api::StatusCode::FailedPrecondition as i32, None);
    }
    let bind_address = listen.bind_address.clone();
    // Carrier binds are synchronous and block the runtime thread
    // (Handle::block_on); block_in_place moves off the async machinery
    // (the same pattern as carriers.rs `bind_tcp`).
    let result = tokio::task::block_in_place(|| carrier.listen(bind_address.clone()));
    match result {
        Ok(listener) => {
            // Service the new listener immediately: the spawned accept loop
            // owns it (keeping the socket alive), so runtime binds actually
            // accept connections instead of queueing in the backlog.
            if let Some(accept_state) = state.self_arc.upgrade() {
                let carrier_type = listen.carrier_type.clone();
                tokio::spawn(async move {
                    crate::accept_loop(&accept_state, carrier_type, listener).await;
                });
            } else {
                log::warn!("[carrier] runtime listener not serviced: state gone");
            }
            let response = ListenResponse {
                bound_address: bind_address,
            };
            let mut payload = Vec::new();
            Message::encode(&response, &mut payload).expect("encode");
            (api::StatusCode::Ok as i32, Some(payload))
        }
        Err(e) => {
            log::warn!(
                "[carrier] {} listen on {} failed: {e:?}",
                listen.carrier_type,
                listen.bind_address
            );
            (api::StatusCode::FailedPrecondition as i32, None)
        }
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
    use umc_core::trust::TrustLevel;

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
        assert_eq!(status.privacy_profile, "p0");
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

    #[test]
    fn destination_key_hint_seals_create_payload() {
        let destination = umc_crypto::signatures::StaticHandshakeKeyPair::generate();
        let sealed = seal_bundle_for_hint(b"secret", &destination.public().0);
        let envelope = umc_bundle::envelope::BundleEnvelope::decode(&sealed).expect("envelope");
        assert_eq!(
            umc_bundle::envelope::open_bundle(&destination, &envelope).expect("open"),
            b"secret"
        );
        assert_ne!(sealed, b"secret");
    }

    #[test]
    fn bundles_survive_state_reopen() {
        with_password("test-password", || {
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
            let listing =
                api::ListBundlesResponse::decode(decode_response(&bytes).payload.as_slice())
                    .expect("payload")
                    .bundles;
            assert_eq!(listing.len(), 1);
            assert_eq!(listing[0].bundle_id, created.bundle_id);
            assert_eq!(listing[0].payload_size, 10);
        });
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

    fn record_peer(state: &mut RuntimeState, id: u64, now: Instant) {
        state
            .discovery
            .record_candidate(
                umc_discovery::provider::PeerCandidate {
                    candidate_id: id,
                    carrier_type: "ump.udp/1".into(),
                    connection_hint: vec![1, 2, 3],
                    source: umc_discovery::provider::CandidateSource::PeerHint,
                    created_at: now,
                    expires_at: Instant(now.0 + 600_000),
                    sharing_policy: umc_discovery::provider::SharingPolicy::ShareGeneral,
                    authentication: umc_discovery::provider::CandidateAuth::Unauthenticated,
                    local: false,
                },
                now,
            )
            .unwrap();
    }

    #[test]
    fn get_peer_round_trip_and_not_found() {
        let (mut state, _tx) = test_state();
        let now = state.node.clock.as_ref().now();
        record_peer(&mut state, 42, now);

        let get = api::GetPeerRequest {
            endpoint_id: 42u64.to_be_bytes().to_vec(),
        };
        let mut payload = Vec::new();
        Message::encode(&get, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "GetPeer", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        let got = api::GetPeerResponse::decode(response.payload.as_slice()).expect("payload");
        let peer = got.peer.expect("peer");
        assert_eq!(peer.endpoint_id, 42u64.to_be_bytes());
        assert_eq!(peer.label, "ump.udp/1");
        assert_eq!(peer.carrier_hint_count, 1);
        let hint = &got.hints[0];
        assert_eq!(hint.carrier_type_id, "ump.udp/1");
        assert_eq!(hint.connection_hint, vec![1, 2, 3]);
        assert_eq!(hint.source, "peer-hint");

        // An unknown id is NotFound.
        let get = api::GetPeerRequest {
            endpoint_id: 99u64.to_be_bytes().to_vec(),
        };
        let mut payload = Vec::new();
        Message::encode(&get, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "GetPeer", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );

        // A non-8-byte endpoint id is InvalidArgument.
        let get = api::GetPeerRequest {
            endpoint_id: vec![1, 2, 3],
        };
        let mut payload = Vec::new();
        Message::encode(&get, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "GetPeer", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
    }

    #[test]
    fn add_peer_hint_records_a_candidate() {
        let (mut state, _tx) = test_state();
        let add = api::AddPeerHintRequest {
            endpoint_id: 7u64.to_be_bytes().to_vec(),
            hint: Some(api::PeerHint {
                carrier_type_id: "ump.tcp/1".into(),
                connection_hint: vec![9, 9],
                expires_at_unix_ms: i64::try_from(wall_now().0).unwrap_or(i64::MAX) + 600_000,
                source: "operator".into(),
                do_not_reshare: true,
            }),
        };
        let mut payload = Vec::new();
        Message::encode(&add, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "AddPeerHint", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        let peer = api::AddPeerHintResponse::decode(response.payload.as_slice())
            .expect("payload")
            .peer
            .expect("peer");
        assert_eq!(peer.endpoint_id, 7u64.to_be_bytes());

        // The hint became a candidate: listed, with the resharing policy
        // honoring do_not_reshare.
        let snapshot = state.discovery.candidates();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].candidate_id, 7);
        assert_eq!(
            snapshot[0].sharing_policy,
            umc_discovery::provider::SharingPolicy::DoNotReshare
        );

        // An already-expired hint is refused.
        let add = api::AddPeerHintRequest {
            endpoint_id: 8u64.to_be_bytes().to_vec(),
            hint: Some(api::PeerHint {
                carrier_type_id: "ump.tcp/1".into(),
                connection_hint: Vec::new(),
                expires_at_unix_ms: 0,
                source: "operator".into(),
                do_not_reshare: false,
            }),
        };
        let mut payload = Vec::new();
        Message::encode(&add, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "AddPeerHint", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
    }

    #[test]
    fn remove_peer_clears_table_and_persisted_record() {
        let (mut state, _tx) = test_state();
        let now = state.node.clock.as_ref().now();
        record_peer(&mut state, 42, now);
        assert!(
            state
                .store
                .get(Namespace::Peer, &42u64.to_be_bytes())
                .unwrap()
                .is_some(),
            "recorded candidates persist (storage.md §16.4)"
        );

        let remove = api::RemovePeerRequest {
            endpoint_id: 42u64.to_be_bytes().to_vec(),
            expected_revision: None,
        };
        let mut payload = Vec::new();
        Message::encode(&remove, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "RemovePeer", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);

        assert!(state.discovery.candidates().is_empty());
        assert!(
            state
                .store
                .get(Namespace::Peer, &42u64.to_be_bytes())
                .unwrap()
                .is_none(),
            "the persisted record is deleted too"
        );

        // Removing an unknown peer is NotFound.
        let remove = api::RemovePeerRequest {
            endpoint_id: 43u64.to_be_bytes().to_vec(),
            expected_revision: None,
        };
        let mut payload = Vec::new();
        Message::encode(&remove, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "RemovePeer", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    fn set_trust_raw(state: &mut RuntimeState, endpoint: &[u8; 32], proto_state: i32) -> i32 {
        let set = api::SetTrustStateRequest {
            endpoint_id: endpoint.to_vec(),
            trust_state: proto_state,
            expected_revision: None,
            reason: "test".into(),
        };
        let mut payload = Vec::new();
        Message::encode(&set, &mut payload).unwrap();
        let bytes = dispatch_request(
            state,
            &request("PeerService", "SetTrustState", payload),
            None,
        );
        decode_response(&bytes).status.unwrap().code
    }

    #[test]
    fn set_trust_state_moves_effective_level_and_emits_event() {
        let (mut state, _tx) = test_state();
        let endpoint = [4u8; 32];
        assert_eq!(
            state
                .trust_store()
                .effective_trust_level(&endpoint)
                .unwrap(),
            TrustLevel::Unknown,
            "unseen endpoints start at the default"
        );

        assert_eq!(
            set_trust_raw(&mut state, &endpoint, api::TrustState::Trusted as i32),
            api::StatusCode::Ok as i32
        );
        assert_eq!(
            state
                .trust_store()
                .effective_trust_level(&endpoint)
                .unwrap(),
            TrustLevel::Familiar,
            "TRUSTED maps to the v1 Familiar level"
        );

        assert_eq!(
            set_trust_raw(&mut state, &endpoint, api::TrustState::Restricted as i32),
            api::StatusCode::Ok as i32
        );
        assert_eq!(
            state
                .trust_store()
                .effective_trust_level(&endpoint)
                .unwrap(),
            TrustLevel::Distrusted,
            "RESTRICTED marks the peer distrusted"
        );

        // UNKNOWN restores the default (the trust record is removed).
        assert_eq!(
            set_trust_raw(&mut state, &endpoint, api::TrustState::Unknown as i32),
            api::StatusCode::Ok as i32
        );
        assert_eq!(
            state
                .trust_store()
                .effective_trust_level(&endpoint)
                .unwrap(),
            TrustLevel::Unknown
        );

        // The mutation is audited in the event log.
        let events = state.events.lock().unwrap().recent(10);
        assert!(
            events.iter().any(|event| event.kind == "trust_state_set"),
            "SetTrustState emits a trust event"
        );

        // UNSPECIFIED is refused.
        assert_eq!(
            set_trust_raw(&mut state, &endpoint, api::TrustState::Unspecified as i32),
            api::StatusCode::InvalidArgument as i32
        );
        // A non-32-byte endpoint id is refused.
        let set = api::SetTrustStateRequest {
            endpoint_id: vec![1, 2],
            trust_state: api::TrustState::Trusted as i32,
            expected_revision: None,
            reason: "test".into(),
        };
        let mut payload = Vec::new();
        Message::encode(&set, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "SetTrustState", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
    }

    #[test]
    fn block_peer_refuses_new_sessions_and_unblock_restores() {
        let (mut state, _tx) = test_state();
        let endpoint = [9u8; 32];
        let now = state.node.clock.as_ref().now();

        let block = api::BlockPeerRequest {
            endpoint_id: endpoint.to_vec(),
            reason: "abuse".into(),
            expires_at_unix_ms: 0,
        };
        let mut payload = Vec::new();
        Message::encode(&block, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "BlockPeer", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        let peer = api::BlockPeerResponse::decode(response.payload.as_slice())
            .expect("payload")
            .peer
            .expect("peer");
        assert_eq!(peer.trust_state, api::TrustState::Blocked as i32);

        // The accept loop refuses new sessions from the blocked peer
        // (register_session consults the blocklist).
        assert!(
            state.refuse_if_blocked(&endpoint, now).is_err(),
            "a blocked peer's session attempt is refused"
        );
        assert!(
            state.refuse_if_blocked(&[8u8; 32], now).is_ok(),
            "other peers are unaffected"
        );

        let unblock = api::UnblockPeerRequest {
            endpoint_id: endpoint.to_vec(),
            expected_revision: None,
        };
        let mut payload = Vec::new();
        Message::encode(&unblock, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "UnblockPeer", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        assert!(state.refuse_if_blocked(&endpoint, now).is_ok());

        // A short endpoint id is refused.
        let block = api::BlockPeerRequest {
            endpoint_id: vec![1, 2],
            reason: "abuse".into(),
            expires_at_unix_ms: 0,
        };
        let mut payload = Vec::new();
        Message::encode(&block, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "BlockPeer", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
    }

    #[allow(clippy::too_many_lines)] // one invitation lifecycle: create, import, consume, revoke
    #[test]
    fn invitation_create_import_revoke_round_trip() {
        let (mut state, _tx) = test_state();
        let scope = api::InvitationScope {
            endpoint_ids: vec![42u64.to_be_bytes().to_vec()],
            protocol_ids: vec!["ump.tcp/1".into()],
            allow_relay: false,
            allow_discovery: true,
            maximum_uses: 1,
            expires_at_unix_ms: i64::try_from(wall_now().0).unwrap_or(i64::MAX) + 3_600_000,
        };
        let create = api::CreateInvitationRequest {
            identity_handle: Some(api::OpaqueHandle {
                value: NODE_IDENTITY_RECORD.to_vec(),
            }),
            scope: Some(scope.clone()),
        };
        let mut payload = Vec::new();
        Message::encode(&create, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "CreateInvitation", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        let created =
            api::CreateInvitationResponse::decode(response.payload.as_slice()).expect("payload");
        assert_eq!(created.invitation_id.len(), 16);
        assert_eq!(created.invitation_secret.len(), 32);
        assert!(!created.invitation_document.is_empty());

        // Import round trip: validates the invitation and records the
        // invited endpoint as an invitation-authenticated candidate.
        let import = api::ImportInvitationRequest {
            invitation_document: created.invitation_document.clone(),
            invitation_secret: created.invitation_secret.clone(),
        };
        let mut payload = Vec::new();
        Message::encode(&import, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "ImportInvitation", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        let imported =
            api::ImportInvitationResponse::decode(response.payload.as_slice()).expect("payload");
        assert_eq!(imported.invitation_id, created.invitation_id);
        assert_eq!(imported.scope, Some(scope));
        let candidates = state.discovery.candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].candidate_id, 42);
        assert_eq!(
            candidates[0].authentication,
            umc_discovery::provider::CandidateAuth::InvitationAuthenticated
        );
        assert_eq!(
            candidates[0].source,
            umc_discovery::provider::CandidateSource::Invitation
        );

        // A single-use invitation imports exactly once.
        let mut payload = Vec::new();
        Message::encode(&import, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "ImportInvitation", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::FailedPrecondition as i32,
            "single-use invitations are consumed by the first import"
        );

        // Revoke: the invitation no longer validates.
        let revoke = api::RevokeInvitationRequest {
            invitation_id: created.invitation_id.clone(),
            reason: "expired".into(),
        };
        let mut payload = Vec::new();
        Message::encode(&revoke, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "RevokeInvitation", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );
        let mut payload = Vec::new();
        Message::encode(&import, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "ImportInvitation", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32,
            "a revoked invitation is unknown"
        );

        // An unknown issuing identity is NotFound.
        let create = api::CreateInvitationRequest {
            identity_handle: Some(api::OpaqueHandle {
                value: b"nobody".to_vec(),
            }),
            scope: Some(api::InvitationScope {
                endpoint_ids: vec![],
                protocol_ids: vec![],
                allow_relay: false,
                allow_discovery: false,
                maximum_uses: 0,
                expires_at_unix_ms: i64::try_from(wall_now().0).unwrap_or(i64::MAX) + 3_600_000,
            }),
        };
        let mut payload = Vec::new();
        Message::encode(&create, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("PeerService", "CreateInvitation", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    #[test]
    fn get_route_and_probe_round_trip() {
        let (mut state, _tx) = test_state();
        let now = state.node.clock.as_ref().now();
        let rid = [1u8; 16];
        let hash = crate::session_task::hash_destination(b"peer-a");
        state
            .routing
            .admit_route_request(&rid, b"upstream", 0, 8, 30_000, &[b"peer-a".to_vec()], now)
            .unwrap();
        let _ = state.routing.record_route_response(
            umc_routing::types::RouteKey {
                destination_profile: 0,
                destination_hash: hash,
                scope: umc_routing::types::RouteScope::General,
                policy_class: 0,
            },
            rid,
            "hop-a".into(),
            600_000,
            now,
        );

        // GetRoute by the key-hash handle.
        let get = api::GetRouteRequest {
            route_handle: Some(api::OpaqueHandle {
                value: hash.to_vec(),
            }),
        };
        let mut payload = Vec::new();
        Message::encode(&get, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("RouteService", "GetRoute", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        let route = api::GetRouteResponse::decode(response.payload.as_slice())
            .expect("payload")
            .route
            .expect("route");
        assert_eq!(route.destination_hint_hash, hash);
        assert_eq!(route.state, "usable");
        assert_eq!(route.carrier_class, "hop-a");

        // An unknown hash is NotFound.
        let get = api::GetRouteRequest {
            route_handle: Some(api::OpaqueHandle {
                value: [9u8; 32].to_vec(),
            }),
        };
        let mut payload = Vec::new();
        Message::encode(&get, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("RouteService", "GetRoute", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );

        // ProbeRoute: a cache probe returns the learned route for the hint.
        let probe = api::ProbeRouteRequest {
            destination_hint: b"peer-a".to_vec(),
            policy: None,
            wait_for_usable: true,
        };
        let mut payload = Vec::new();
        Message::encode(&probe, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("RouteService", "ProbeRoute", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        let probed = api::ProbeRouteResponse::decode(response.payload.as_slice()).expect("payload");
        assert_eq!(probed.candidates.len(), 1);
        assert_eq!(probed.candidates[0].destination_hint_hash, hash);
        assert_eq!(probed.operation_handle.unwrap().value, hash);

        // An unknown destination yields no candidates.
        let probe = api::ProbeRouteRequest {
            destination_hint: b"nobody".to_vec(),
            policy: None,
            wait_for_usable: false,
        };
        let mut payload = Vec::new();
        Message::encode(&probe, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("RouteService", "ProbeRoute", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        let probed = api::ProbeRouteResponse::decode(response.payload.as_slice()).expect("payload");
        assert!(probed.candidates.is_empty());
    }

    #[test]
    fn invalidate_route_clears_cache_and_persisted_record() {
        let (mut state, _tx) = test_state();
        let now = state.node.clock.as_ref().now();
        let rid = [2u8; 16];
        let hash = crate::session_task::hash_destination(b"peer-b");
        let key = umc_routing::types::RouteKey {
            destination_profile: 0,
            destination_hash: hash,
            scope: umc_routing::types::RouteScope::General,
            policy_class: 0,
        };
        state
            .routing
            .admit_route_request(&rid, b"upstream", 0, 8, 30_000, &[], now)
            .unwrap();
        let _ = state
            .routing
            .record_route_response(key.clone(), rid, "hop-b".into(), 600_000, now);
        assert!(state.routing.find_route(&key, now).is_some());
        assert_eq!(
            umc_storage::records::list_routes(state.store.as_ref())
                .unwrap()
                .len(),
            1,
            "learned routes persist (storage.md §15.1)"
        );

        let invalidate = api::InvalidateRouteRequest {
            route_handle: Some(api::OpaqueHandle {
                value: hash.to_vec(),
            }),
            reason: "stale".into(),
        };
        let mut payload = Vec::new();
        Message::encode(&invalidate, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("RouteService", "InvalidateRoute", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);

        assert!(
            state.routing.find_route(&key, now).is_none(),
            "the cache entry is gone"
        );
        assert!(
            umc_storage::records::list_routes(state.store.as_ref())
                .unwrap()
                .is_empty(),
            "the persisted snapshot is gone"
        );

        // Invalidating an unknown route is NotFound.
        let invalidate = api::InvalidateRouteRequest {
            route_handle: Some(api::OpaqueHandle {
                value: [9u8; 32].to_vec(),
            }),
            reason: "stale".into(),
        };
        let mut payload = Vec::new();
        Message::encode(&invalidate, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("RouteService", "InvalidateRoute", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    #[tokio::test]
    async fn close_session_aborts_the_session_task() {
        let (mut state, _tx) = test_state();
        let task = tokio::spawn(std::future::pending::<()>());
        let id = state.sessions.next_id();
        state.sessions.register(
            id,
            crate::session_manager::SessionEntry {
                peer_endpoint_id: [7u8; 32],
                carrier_type: "ump.tcp/1".into(),
                task: task.abort_handle(),
                established_at_ms: 1_000,
            },
        );

        let close = api::CloseSessionRequest {
            session_handle: Some(api::OpaqueHandle {
                value: id.to_be_bytes().to_vec(),
            }),
            application_error_code: 0,
            reason: "operator".into(),
        };
        let mut payload = Vec::new();
        Message::encode(&close, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "CloseSession", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        assert!(
            task.await.is_err(),
            "the session task was aborted by CloseSession"
        );
        assert!(
            state.sessions.lookup(id).unwrap().task.is_finished(),
            "the registry entry's abort handle reports the finished task"
        );

        // An unknown handle is NotFound.
        let close = api::CloseSessionRequest {
            session_handle: Some(api::OpaqueHandle {
                value: 999u64.to_be_bytes().to_vec(),
            }),
            application_error_code: 0,
            reason: "operator".into(),
        };
        let mut payload = Vec::new();
        Message::encode(&close, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "CloseSession", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    #[tokio::test]
    async fn list_streams_known_session_returns_empty_listing() {
        let (mut state, _tx) = test_state();
        let id = state.sessions.next_id();
        register_session(&state, id, [7u8; 32]);

        let list = api::ListStreamsRequest {
            session_handle: Some(api::OpaqueHandle {
                value: id.to_be_bytes().to_vec(),
            }),
            page: None,
        };
        let mut payload = Vec::new();
        Message::encode(&list, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "ListStreams", payload),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(response.status.unwrap().code, api::StatusCode::Ok as i32);
        let streams = api::ListStreamsResponse::decode(response.payload.as_slice())
            .expect("payload")
            .streams;
        assert!(
            streams.is_empty(),
            "v1 registry tracks no open streams (documented minimal)"
        );

        // An unknown session is NotFound.
        let list = api::ListStreamsRequest {
            session_handle: Some(api::OpaqueHandle {
                value: 999u64.to_be_bytes().to_vec(),
            }),
            page: None,
        };
        let mut payload = Vec::new();
        Message::encode(&list, &mut payload).unwrap();
        let bytes = dispatch_request(
            &mut state,
            &request("SessionService", "ListStreams", payload),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
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
        state.config.privacy_profile = "p1".into();
        state.config.privacy_policy_override = Some("p2".into());
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
        assert!(config
            .entries
            .iter()
            .any(|e| e.key == "disabled_protocol_versions"));
        assert!(config
            .entries
            .iter()
            .any(|e| e.key == "disable_public_relay"));
        assert!(config
            .entries
            .iter()
            .any(|e| e.key == "privacy_profile" && e.value == "p2"));
        assert!(config
            .entries
            .iter()
            .any(|e| e.key == "privacy_policy_override" && e.value == "p2"));
    }

    #[test]
    fn emergency_public_relay_disablement_refuses_public_opens() {
        let (mut state, _tx) = test_state();
        state.config.disable_public_relay = true;
        let open = OpenCircuitRequest {
            requested_lifetime_ms: 60_000,
            requested_byte_quota: 1_024,
            flags: 0,
            bidirectional: true,
            private_handling: false,
            peer_circuits: 0,
        };
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "OpenCircuit", encode_request(&open)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::PermissionDenied as i32
        );

        let private = OpenCircuitRequest {
            private_handling: true,
            ..open
        };
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "OpenCircuit", encode_request(&private)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32,
            "private relay handling remains available during a public-relay shutdown"
        );
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

    // --- Task F2: IdentityService + CarrierService dispatch ---

    /// Runs `f` with `UMC_KEYSTORE_PASSWORD` set; env mutation is
    /// serialized with every other keystore test in the crate via the
    /// shared test lock.
    fn with_password(password: &str, f: impl FnOnce()) {
        let _guard = crate::state::KEYSTORE_PASSWORD_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::set_var("UMC_KEYSTORE_PASSWORD", password);
        f();
        std::env::remove_var("UMC_KEYSTORE_PASSWORD");
    }

    fn encode_request<M: prost::Message>(message: &M) -> Vec<u8> {
        let mut payload = Vec::new();
        message.encode(&mut payload).expect("encode");
        payload
    }

    fn identity_handle(record_name: &str) -> api::OpaqueHandle {
        api::OpaqueHandle {
            value: record_name.as_bytes().to_vec(),
        }
    }

    #[test]
    fn list_identities_shows_primary_then_secondaries() {
        with_password("test-password", || {
            let (mut state, _tx) = test_state();
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "ListIdentities", vec![]),
                None,
            );
            let response = decode_response(&bytes);
            assert_eq!(
                response.status.as_ref().unwrap().code,
                api::StatusCode::Ok as i32
            );
            let list = api::ListIdentitiesResponse::decode(response.payload.as_slice())
                .expect("payload")
                .identities;
            assert_eq!(list.len(), 1, "the primary is always listed");
            assert_eq!(list[0].kind, api::IdentityKind::NodeManagement as i32);
            assert_eq!(
                list[0].endpoint_id,
                state.node_identity.endpoint_id(),
                "the primary's endpoint id round-trips"
            );
            let primary_handle = list[0]
                .identity_handle
                .as_ref()
                .expect("handle")
                .value
                .clone();
            assert_eq!(primary_handle, b"node-identity");

            // Create a secondary through the dispatcher; the node identity
            // is untouched.
            let create = api::CreateIdentityRequest {
                kind: api::IdentityKind::UserEndpoint as i32,
                label: "alice".into(),
                binding_lifetime_ms: 0,
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "CreateIdentity", encode_request(&create)),
                None,
            );
            let created =
                api::CreateIdentityResponse::decode(decode_response(&bytes).payload.as_slice())
                    .expect("payload")
                    .identity
                    .expect("identity");
            assert_eq!(created.kind, api::IdentityKind::UserEndpoint as i32);
            assert_eq!(created.label, "alice");
            assert_eq!(created.binding_sequence, 0, "fresh secondaries start at 0");
            assert_ne!(
                created.endpoint_id,
                state.node_identity.endpoint_id(),
                "the secondary is a different identity"
            );

            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "ListIdentities", vec![]),
                None,
            );
            let list =
                api::ListIdentitiesResponse::decode(decode_response(&bytes).payload.as_slice())
                    .expect("payload")
                    .identities;
            assert_eq!(list.len(), 2);
            assert_eq!(
                list[1].identity_handle.as_ref().unwrap().value,
                b"secondary-0"
            );
        });
    }

    #[test]
    fn get_identity_resolves_by_endpoint_and_handle() {
        with_password("test-password", || {
            let (mut state, _tx) = test_state();
            let create = api::CreateIdentityRequest {
                kind: api::IdentityKind::UserEndpoint as i32,
                label: "alice".into(),
                binding_lifetime_ms: 0,
            };
            dispatch_request(
                &mut state,
                &request("IdentityService", "CreateIdentity", encode_request(&create)),
                None,
            );
            let secondary_endpoint = state.secondaries[0].identity.endpoint_id();

            // By endpoint id: the secondary resolves.
            let get = api::GetIdentityRequest {
                identity: Some(api::get_identity_request::Identity::EndpointId(
                    secondary_endpoint.to_vec(),
                )),
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "GetIdentity", encode_request(&get)),
                None,
            );
            let response = decode_response(&bytes);
            assert_eq!(
                response.status.as_ref().unwrap().code,
                api::StatusCode::Ok as i32
            );
            let got =
                api::GetIdentityResponse::decode(response.payload.as_slice()).expect("payload");
            assert_eq!(got.identity.expect("identity").label, "alice");
            assert!(
                !got.public_binding.is_empty(),
                "the signed binding is the public material"
            );

            // By handle: the primary resolves with its own endpoint.
            let get = api::GetIdentityRequest {
                identity: Some(api::get_identity_request::Identity::Handle(
                    identity_handle("node-identity"),
                )),
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "GetIdentity", encode_request(&get)),
                None,
            );
            let got = api::GetIdentityResponse::decode(decode_response(&bytes).payload.as_slice())
                .expect("payload")
                .identity
                .expect("identity");
            assert_eq!(got.endpoint_id, state.node_identity.endpoint_id().to_vec());

            // An unknown endpoint is NotFound; an empty oneof is
            // InvalidArgument.
            let get = api::GetIdentityRequest {
                identity: Some(api::get_identity_request::Identity::EndpointId(vec![
                    0u8;
                    32
                ])),
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "GetIdentity", encode_request(&get)),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::NotFound as i32
            );
            let bytes = dispatch_request(
                &mut state,
                &request(
                    "IdentityService",
                    "GetIdentity",
                    encode_request(&api::GetIdentityRequest::default()),
                ),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::InvalidArgument as i32
            );
        });
    }

    #[test]
    fn rotate_handshake_key_increments_sequence_and_round_trips() {
        with_password("test-password", || {
            let dir = std::env::temp_dir().join(format!(
                "umcd-rotate-handshake-{}-{}",
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
            let old_static = state.node_identity.static_handshake.public();
            let old_sequence = state.primary_binding.sequence;

            let rotate = api::RotateHandshakeKeyRequest {
                identity_handle: Some(identity_handle("node-identity")),
                expected_revision: Some(api::ResourceRevision {
                    value: old_sequence,
                }),
                new_binding_lifetime_ms: 0,
            };
            let bytes = dispatch_request(
                &mut state,
                &request(
                    "IdentityService",
                    "RotateHandshakeKey",
                    encode_request(&rotate),
                ),
                None,
            );
            let response = decode_response(&bytes);
            assert_eq!(
                response.status.as_ref().unwrap().code,
                api::StatusCode::Ok as i32
            );
            let rotated = api::RotateHandshakeKeyResponse::decode(response.payload.as_slice())
                .expect("payload");
            let summary = rotated.identity.expect("identity");
            assert_eq!(
                summary.binding_sequence,
                old_sequence + 1,
                "the binding sequence increments"
            );
            assert_ne!(
                state.node_identity.static_handshake.public(),
                old_static,
                "the node switches to the new static key"
            );
            assert_eq!(state.primary_binding.sequence, old_sequence + 1);
            drop(state);

            // Keystore round-trip after rotation: a fresh daemon restores
            // the new static key and the incremented sequence.
            let (tx2, _rx2) = tokio::sync::mpsc::channel::<()>(1);
            let reopened = RuntimeState::new(config, tx2).expect("reopened runtime state");
            assert_ne!(
                reopened.node_identity.static_handshake.public(),
                old_static,
                "the rotated static key survives restart"
            );
            assert_eq!(reopened.primary_binding.sequence, old_sequence + 1);
        });
    }

    #[test]
    fn rotate_identity_key_changes_endpoint_and_persists() {
        with_password("test-password", || {
            let dir = std::env::temp_dir().join(format!(
                "umcd-rotate-identity-{}-{}",
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
            let old_endpoint = state.node_identity.endpoint_id();

            let rotate = api::RotateIdentityKeyRequest {
                identity_handle: Some(identity_handle("node-identity")),
                expected_revision: None,
                require_old_key_signature: false,
            };
            let bytes = dispatch_request(
                &mut state,
                &request(
                    "IdentityService",
                    "RotateIdentityKey",
                    encode_request(&rotate),
                ),
                None,
            );
            let response = decode_response(&bytes);
            assert_eq!(
                response.status.as_ref().unwrap().code,
                api::StatusCode::Ok as i32
            );
            let rotated = api::RotateIdentityKeyResponse::decode(response.payload.as_slice())
                .expect("payload");
            let summary = rotated.identity.expect("identity");
            assert_ne!(
                summary.endpoint_id,
                old_endpoint.to_vec(),
                "a full identity change means a new endpoint id"
            );
            assert_eq!(summary.binding_sequence, 1);
            assert_eq!(
                rotated.rotation_proof.len(),
                64,
                "the new binding's signature"
            );
            assert_eq!(
                state.node.config.dcid,
                summary.endpoint_id[..8],
                "the node dcid follows the new endpoint"
            );
            assert_eq!(
                state.ticket_key,
                crate::state::ticket_key_for(&state.node_identity),
                "the ticket key follows the new identity"
            );
            drop(state);

            let (tx2, _rx2) = tokio::sync::mpsc::channel::<()>(1);
            let reopened = RuntimeState::new(config, tx2).expect("reopened runtime state");
            assert_eq!(
                reopened.node_identity.endpoint_id().to_vec(),
                summary.endpoint_id
            );
            assert_eq!(reopened.primary_binding.sequence, 1);
        });
    }

    #[test]
    fn rotation_rejects_stale_revisions_and_unknown_handles() {
        with_password("test-password", || {
            let (mut state, _tx) = test_state();
            // Stale expected_revision → Conflict.
            let rotate = api::RotateHandshakeKeyRequest {
                identity_handle: Some(identity_handle("node-identity")),
                expected_revision: Some(api::ResourceRevision { value: 99 }),
                new_binding_lifetime_ms: 0,
            };
            let bytes = dispatch_request(
                &mut state,
                &request(
                    "IdentityService",
                    "RotateHandshakeKey",
                    encode_request(&rotate),
                ),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::Conflict as i32
            );
            // Unknown handle → NotFound.
            let rotate = api::RotateHandshakeKeyRequest {
                identity_handle: Some(identity_handle("no-such-identity")),
                expected_revision: None,
                new_binding_lifetime_ms: 0,
            };
            let bytes = dispatch_request(
                &mut state,
                &request(
                    "IdentityService",
                    "RotateHandshakeKey",
                    encode_request(&rotate),
                ),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::NotFound as i32
            );
            // require_old_key_signature is unsupported → InvalidArgument.
            let rotate = api::RotateIdentityKeyRequest {
                identity_handle: Some(identity_handle("node-identity")),
                expected_revision: None,
                require_old_key_signature: true,
            };
            let bytes = dispatch_request(
                &mut state,
                &request(
                    "IdentityService",
                    "RotateIdentityKey",
                    encode_request(&rotate),
                ),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::InvalidArgument as i32
            );
        });
    }

    #[test]
    fn secret_export_is_gated_and_import_round_trips() {
        with_password("test-password", || {
            let (mut state, _tx) = test_state();
            // Default config: secret export is PermissionDenied.
            let export = api::ExportSecretIdentityRequest {
                identity_handle: Some(identity_handle("node-identity")),
                ..Default::default()
            };
            let bytes = dispatch_request(
                &mut state,
                &request(
                    "IdentityService",
                    "ExportSecretIdentity",
                    encode_request(&export),
                ),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::PermissionDenied as i32
            );
            assert_eq!(state.secondaries.len(), 0, "nothing was written");

            // With the flag on, the raw seeds come back and import them as
            // a secondary round-trips.
            state.config.allow_secret_export = true;
            let bytes = dispatch_request(
                &mut state,
                &request(
                    "IdentityService",
                    "ExportSecretIdentity",
                    encode_request(&export),
                ),
                None,
            );
            let response = decode_response(&bytes);
            assert_eq!(
                response.status.as_ref().unwrap().code,
                api::StatusCode::Ok as i32
            );
            let seeds = api::ExportSecretIdentityResponse::decode(response.payload.as_slice())
                .expect("payload")
                .encrypted_export;
            assert_eq!(seeds.len(), 64, "raw identity_seed || static_seed");
            assert_eq!(
                state.node_identity.identity.to_seed(),
                seeds[..32],
                "the primary's identity seed is exported"
            );

            // Importing the same material produces a secondary with the
            // SAME endpoint id — the primary is untouched.
            let import = api::ImportIdentityRequest {
                encrypted_export: seeds.clone(),
                validate_only: false,
                ..Default::default()
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "ImportIdentity", encode_request(&import)),
                None,
            );
            let imported =
                api::ImportIdentityResponse::decode(decode_response(&bytes).payload.as_slice())
                    .expect("payload")
                    .identity
                    .expect("identity");
            assert_eq!(
                imported.endpoint_id,
                state.node_identity.endpoint_id().to_vec(),
                "import reconstructs the exported identity"
            );
            assert_ne!(
                imported.identity_handle.as_ref().unwrap().value,
                b"node-identity",
                "import always creates a secondary"
            );
            assert_eq!(state.secondaries.len(), 1);

            // validate_only does not store.
            let import = api::ImportIdentityRequest {
                encrypted_export: seeds,
                validate_only: true,
                ..Default::default()
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "ImportIdentity", encode_request(&import)),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::Ok as i32
            );
            assert_eq!(state.secondaries.len(), 1, "validate-only stores nothing");

            // Malformed seeds are InvalidArgument.
            let import = api::ImportIdentityRequest {
                encrypted_export: vec![1u8; 32],
                ..Default::default()
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "ImportIdentity", encode_request(&import)),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::InvalidArgument as i32
            );
        });
    }

    #[test]
    fn delete_identity_removes_secondaries_only() {
        with_password("test-password", || {
            let (mut state, _tx) = test_state();
            // The primary is not deletable.
            let delete = api::DeleteIdentityRequest {
                identity_handle: Some(identity_handle("node-identity")),
                plan_only: false,
                ..Default::default()
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "DeleteIdentity", encode_request(&delete)),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::FailedPrecondition as i32
            );

            // Create a secondary, then delete it; the list returns to 1.
            let create = api::CreateIdentityRequest {
                kind: api::IdentityKind::ServiceEndpoint as i32,
                label: "ephemeral".into(),
                binding_lifetime_ms: 0,
            };
            dispatch_request(
                &mut state,
                &request("IdentityService", "CreateIdentity", encode_request(&create)),
                None,
            );
            let handle = state.secondaries[0].record_name.as_bytes().to_vec();

            let delete = api::DeleteIdentityRequest {
                identity_handle: Some(api::OpaqueHandle {
                    value: handle.clone(),
                }),
                plan_only: false,
                ..Default::default()
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "DeleteIdentity", encode_request(&delete)),
                None,
            );
            let response = decode_response(&bytes);
            assert_eq!(
                response.status.as_ref().unwrap().code,
                api::StatusCode::Ok as i32
            );
            assert!(
                api::DeleteIdentityResponse::decode(response.payload.as_slice())
                    .expect("payload")
                    .deleted
            );
            assert!(state.secondaries.is_empty());
        });
    }

    #[test]
    fn delete_identity_plan_only_and_revision_checks() {
        with_password("test-password", || {
            let (mut state, _tx) = test_state();
            let create = api::CreateIdentityRequest {
                kind: api::IdentityKind::ServiceEndpoint as i32,
                label: "again".into(),
                binding_lifetime_ms: 0,
            };
            dispatch_request(
                &mut state,
                &request("IdentityService", "CreateIdentity", encode_request(&create)),
                None,
            );
            let handle = state.secondaries[0].record_name.as_bytes().to_vec();
            // plan_only reports without deleting.
            let delete = api::DeleteIdentityRequest {
                identity_handle: Some(api::OpaqueHandle {
                    value: handle.clone(),
                }),
                plan_only: true,
                expected_revision: Some(api::ResourceRevision { value: 0 }),
                ..Default::default()
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "DeleteIdentity", encode_request(&delete)),
                None,
            );
            let response = decode_response(&bytes);
            assert_eq!(
                response.status.as_ref().unwrap().code,
                api::StatusCode::Ok as i32
            );
            assert!(
                !api::DeleteIdentityResponse::decode(response.payload.as_slice())
                    .expect("payload")
                    .deleted,
                "plan_only must not delete"
            );
            assert_eq!(state.secondaries.len(), 1);

            // A stale expected_revision is Conflict.
            let delete = api::DeleteIdentityRequest {
                identity_handle: Some(api::OpaqueHandle { value: handle }),
                plan_only: false,
                expected_revision: Some(api::ResourceRevision { value: 99 }),
                ..Default::default()
            };
            let bytes = dispatch_request(
                &mut state,
                &request("IdentityService", "DeleteIdentity", encode_request(&delete)),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::Conflict as i32
            );
            assert_eq!(
                state.secondaries.len(),
                1,
                "a rejected delete changes nothing"
            );
        });
    }

    #[test]
    fn export_public_identity_returns_the_binding() {
        with_password("test-password", || {
            let (mut state, _tx) = test_state();
            let export = api::ExportPublicIdentityRequest {
                identity_handle: Some(identity_handle("node-identity")),
            };
            let bytes = dispatch_request(
                &mut state,
                &request(
                    "IdentityService",
                    "ExportPublicIdentity",
                    encode_request(&export),
                ),
                None,
            );
            let response = decode_response(&bytes);
            assert_eq!(
                response.status.as_ref().unwrap().code,
                api::StatusCode::Ok as i32
            );
            let exported = api::ExportPublicIdentityResponse::decode(response.payload.as_slice())
                .expect("payload")
                .export_bytes;
            assert_eq!(
                exported,
                state.primary_binding.signed_bytes(),
                "the public export is the signed binding"
            );
            // Unknown handle → NotFound.
            let export = api::ExportPublicIdentityRequest {
                identity_handle: Some(identity_handle("nope")),
            };
            let bytes = dispatch_request(
                &mut state,
                &request(
                    "IdentityService",
                    "ExportPublicIdentity",
                    encode_request(&export),
                ),
                None,
            );
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::NotFound as i32
            );
        });
    }

    #[test]
    fn carrier_types_and_properties_round_trip() {
        let (mut state, _tx) = test_state();
        state
            .node
            .register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));

        // ListCarrierTypes reports the registered configured carrier.
        let bytes = dispatch_request(
            &mut state,
            &request("CarrierService", "ListCarrierTypes", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let types = api::ListCarrierTypesResponse::decode(response.payload.as_slice())
            .expect("payload")
            .types;
        assert_eq!(types.len(), 1, "only the registered carrier is listed");
        assert_eq!(types[0].type_id, "ump.tcp/1");
        assert!(types[0].supports_listen);
        assert!(types[0].supports_dial);
        assert!(!types[0].supports_discovery);
        assert!(types[0].maximum_packet_size > 0);

        // GetLinkProperties matches, and an unknown type is NotFound.
        let get = GetLinkPropertiesRequest {
            carrier_type: "ump.tcp/1".into(),
        };
        let bytes = dispatch_request(
            &mut state,
            &request("CarrierService", "GetLinkProperties", encode_request(&get)),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let info = GetLinkPropertiesResponse::decode(response.payload.as_slice())
            .expect("payload")
            .info
            .expect("info");
        assert_eq!(info.type_id, "ump.tcp/1");
        assert_eq!(info, types[0]);

        let get = GetLinkPropertiesRequest {
            carrier_type: "ump.quic/1".into(),
        };
        let bytes = dispatch_request(
            &mut state,
            &request("CarrierService", "GetLinkProperties", encode_request(&get)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    #[tokio::test]
    async fn list_links_and_stats_report_sessions() {
        let (mut state, _tx) = test_state();
        state
            .node
            .register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
        register_session(&state, state.sessions.next_id(), [1u8; 32]);
        register_session(&state, state.sessions.next_id(), [2u8; 32]);

        let bytes = dispatch_request(
            &mut state,
            &request("CarrierService", "ListLinks", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let links = api::ListLinksResponse::decode(response.payload.as_slice())
            .expect("payload")
            .links;
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].carrier_type_id, "ump.tcp/1");
        assert_eq!(links[0].state, "active");
        assert_eq!(
            links[0].carrier_handle.as_ref().unwrap().value,
            b"ump.tcp/1",
            "the carrier type id is the carrier handle"
        );
        assert_eq!(links[0].current_mtu, 0, "the v1 registry tracks no MTU");

        let bytes = dispatch_request(
            &mut state,
            &request("CarrierService", "GetLinkStats", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let link_stats = GetLinkStatsResponse::decode(response.payload.as_slice())
            .expect("payload")
            .stats;
        assert_eq!(link_stats.len(), 1);
        assert_eq!(link_stats[0].carrier_type, "ump.tcp/1");
        assert_eq!(link_stats[0].active_links, 2, "sessions per carrier");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn listen_binds_a_registered_carrier() {
        let (mut state, _tx) = test_state();
        state
            .node
            .register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
        let listen = ListenRequest {
            carrier_type: "ump.tcp/1".into(),
            bind_address: "127.0.0.1:0".into(),
        };
        let bytes = dispatch_request(
            &mut state,
            &request("CarrierService", "Listen", encode_request(&listen)),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let bound = ListenResponse::decode(response.payload.as_slice())
            .expect("payload")
            .bound_address;
        assert_eq!(bound, "127.0.0.1:0", "the requested address is reported");
        // The runtime listener is moved into its accept loop (owned by the
        // spawned task), not parked in the state vector.
        assert!(
            state.listeners.is_empty(),
            "runtime listeners are serviced, not parked"
        );

        // An unknown carrier is NotFound.
        let listen = ListenRequest {
            carrier_type: "ump.quic/1".into(),
            bind_address: "127.0.0.1:0".into(),
        };
        let bytes = dispatch_request(
            &mut state,
            &request("CarrierService", "Listen", encode_request(&listen)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    #[test]
    fn carrier_methods_without_runtime_backing_are_unimplemented() {
        let (mut state, _tx) = test_state();
        // Dial: no outbound initiator yet. CloseLink: no per-link close
        // path yet. Instance lifecycle: single static carrier wiring.
        for (service, method) in [
            ("CarrierService", "Dial"),
            ("CarrierService", "CloseLink"),
            ("CarrierService", "ListCarrierInstances"),
            ("CarrierService", "GetCarrierInstance"),
            ("CarrierService", "CreateCarrierInstance"),
            ("CarrierService", "UpdateCarrierInstance"),
            ("CarrierService", "StartCarrier"),
            ("CarrierService", "StopCarrier"),
            ("CarrierService", "DeleteCarrierInstance"),
        ] {
            let bytes = dispatch_request(&mut state, &request(service, method, vec![]), None);
            assert_eq!(
                decode_response(&bytes).status.unwrap().code,
                api::StatusCode::Unimplemented as i32,
                "{service}.{method} must be Unimplemented"
            );
        }
    }

    #[test]
    fn identity_and_carrier_requests_count_per_service() {
        let (mut state, _tx) = test_state();
        dispatch_request(
            &mut state,
            &request("IdentityService", "ListIdentities", vec![]),
            None,
        );
        dispatch_request(
            &mut state,
            &request("CarrierService", "ListCarrierTypes", vec![]),
            None,
        );
        assert_eq!(
            state
                .metrics
                .get(crate::state::metric_names::CONTROL_REQUESTS_IDENTITY),
            Some(1)
        );
        assert_eq!(
            state
                .metrics
                .get(crate::state::metric_names::CONTROL_REQUESTS_CARRIER),
            Some(1)
        );
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

    #[test]
    fn register_and_unregister_application_round_trip() {
        let (mut state, _tx) = test_state();
        let register = api::RegisterApplicationRequest {
            application_name: "notes".into(),
            application_instance_id: b"instance-1".to_vec(),
            requested_protocol_ids: vec!["org.umc.notes/1".into()],
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "RegisterApplication",
                encode_request(&register),
            ),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let registered =
            api::RegisterApplicationResponse::decode(response.payload.as_slice()).expect("payload");
        // The v1 application handle is the first registered protocol id.
        assert_eq!(
            registered.application_handle.unwrap().value,
            b"org.umc.notes/1"
        );

        // The registry entry exists and the app channel was wired the same
        // way install_echo_app wires the echo application's.
        let handle = state
            .apps
            .lookup(b"org.umc.notes/1")
            .expect("registry entry");
        assert_eq!(handle.service_name, "notes");
        assert!(state
            .app_channels
            .lock()
            .expect("app channels")
            .contains_key(&b"org.umc.notes/1".to_vec()));

        let unregister = api::UnregisterApplicationRequest {
            application_handle: Some(api::OpaqueHandle {
                value: b"org.umc.notes/1".to_vec(),
            }),
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "UnregisterApplication",
                encode_request(&unregister),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );
        assert!(state.apps.lookup(b"org.umc.notes/1").is_none());
        assert!(!state
            .app_channels
            .lock()
            .expect("app channels")
            .contains_key(&b"org.umc.notes/1".to_vec()));

        // Unregistering an unknown app is NotFound, not Ok.
        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "UnregisterApplication",
                encode_request(&unregister),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    #[test]
    fn register_application_retains_channel_receiver() {
        let (mut state, _tx) = test_state();
        let protocol = b"org.umc.notes/1".to_vec();
        let register = api::RegisterApplicationRequest {
            application_name: "notes".into(),
            requested_protocol_ids: vec![String::from_utf8(protocol.clone()).expect("protocol")],
            ..Default::default()
        };

        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "RegisterApplication",
                encode_request(&register),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );

        let sender = state
            .app_channels
            .lock()
            .expect("app channels")
            .get(&protocol)
            .cloned()
            .expect("registered sender");
        let mut receiver = state
            .app_echo_rx
            .lock()
            .expect("app echo receivers")
            .remove(&protocol)
            .expect("registered receiver must stay alive");
        sender
            .try_send_stream_frame(7, b"payload".to_vec())
            .expect("receiver is alive");
        assert_eq!(
            receiver.try_recv_stream_frame().expect("queued frame"),
            (7, b"payload".to_vec())
        );
    }

    #[test]
    fn unregister_application_removes_all_protocols_and_channels() {
        let (mut state, _tx) = test_state();
        let protocols = [b"org.umc.notes/1".to_vec(), b"org.umc.notes/2".to_vec()];
        let register = api::RegisterApplicationRequest {
            application_name: "notes".into(),
            requested_protocol_ids: protocols
                .iter()
                .map(|id| String::from_utf8(id.clone()).expect("protocol"))
                .collect(),
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "RegisterApplication",
                encode_request(&register),
            ),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let handle = api::RegisterApplicationResponse::decode(response.payload.as_slice())
            .expect("payload")
            .application_handle
            .expect("application handle");

        let unregister = api::UnregisterApplicationRequest {
            application_handle: Some(handle),
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "UnregisterApplication",
                encode_request(&unregister),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );
        for protocol in protocols {
            assert!(
                state.apps.lookup(&protocol).is_none(),
                "registry entry must be removed: {protocol:?}"
            );
            assert!(!state
                .app_channels
                .lock()
                .expect("app channels")
                .contains_key(&protocol));
            assert!(!state
                .app_echo_rx
                .lock()
                .expect("app echo receivers")
                .contains_key(&protocol));
        }
    }

    #[test]
    fn register_application_rejects_duplicates_and_bad_input() {
        let (mut state, _tx) = test_state();
        let mut register = api::RegisterApplicationRequest {
            application_name: "echo2".into(),
            requested_protocol_ids: vec!["org.umc.echo2/1".into()],
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "RegisterApplication",
                encode_request(&register),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );

        // A second registration of the same protocol id is AlreadyExists.
        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "RegisterApplication",
                encode_request(&register),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::AlreadyExists as i32
        );
        assert_eq!(state.apps.list().len(), 2, "the echo app plus one more");

        // Missing name or empty protocol list is InvalidArgument.
        register.application_name.clear();
        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "RegisterApplication",
                encode_request(&register),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
        register.application_name = "echo3".into();
        register.requested_protocol_ids.clear();
        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "RegisterApplication",
                encode_request(&register),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
    }

    #[test]
    fn event_subscription_delivers_and_unsubscribes() {
        let (mut state, _tx) = test_state();
        let mut conn = ConnectionState::new();
        let subscribe = api::SubscribeRequest {
            filter: Some(api::EventFilter::default()),
            ..Default::default()
        };
        let response = handle_envelope(
            &mut conn,
            &mut state,
            api::Envelope {
                sequence: 1,
                body: Some(api::envelope::Body::Request(api::Request {
                    request_id: 1,
                    service: "EventService".into(),
                    method: "Subscribe".into(),
                    payload: encode_request(&subscribe),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .expect("subscribe response");
        let response = decode_response(&response);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let handle = api::SubscribeResponse::decode(response.payload.as_slice())
            .expect("subscribe payload")
            .subscription_handle
            .expect("subscription handle");

        push_event(&state, "session_active", "session 1".into());
        let events = drain_event_envelopes(&mut state, &mut conn);
        assert_eq!(events.len(), 1);
        let event = match events[0].body.as_ref().expect("event body") {
            api::envelope::Body::Event(event) => event,
            other => panic!("expected event envelope, got {other:?}"),
        };
        assert_eq!(event.event_sequence, 1);
        assert_eq!(event.event_type, api::EventType::SessionState as i32);

        let unsubscribe = api::UnsubscribeRequest {
            subscription_handle: Some(handle),
        };
        let response = handle_envelope(
            &mut conn,
            &mut state,
            api::Envelope {
                sequence: 2,
                body: Some(api::envelope::Body::Request(api::Request {
                    request_id: 2,
                    service: "EventService".into(),
                    method: "Unsubscribe".into(),
                    payload: encode_request(&unsubscribe),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .expect("unsubscribe response");
        assert_eq!(
            decode_response(&response).status.unwrap().code,
            api::StatusCode::Ok as i32
        );
        push_event(&state, "session_active", "session 2".into());
        assert!(drain_event_envelopes(&mut state, &mut conn).is_empty());
    }

    #[test]
    fn token_service_create_list_inspect_revoke() {
        let (mut state, _tx) = test_state();
        let create = api::CreateTokenRequest {
            label: "test-client".into(),
            grants: vec![api::CapabilityGrant {
                capability: api::Capability::NodeRead as i32,
                ..Default::default()
            }],
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request("TokenService", "CreateToken", encode_request(&create)),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let created =
            api::CreateTokenResponse::decode(response.payload.as_slice()).expect("create payload");
        assert_eq!(created.token.len(), 32);
        let principal = created.token_id.clone();
        assert_eq!(principal.len(), 8);
        assert_eq!(created.effective_grants.len(), 1);

        let list = api::ListGrantsRequest {
            principal_id: principal.clone(),
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request("TokenService", "ListGrants", encode_request(&list)),
            None,
        );
        let listed = api::ListGrantsResponse::decode(decode_response(&bytes).payload.as_slice())
            .expect("list payload");
        assert_eq!(listed.grants.len(), 1);
        assert_eq!(
            listed.grants[0].capability,
            api::Capability::NodeRead as i32
        );

        let revoke = api::RevokeTokenRequest {
            token_id: principal.clone(),
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request("TokenService", "RevokeToken", encode_request(&revoke)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );

        let inspect = api::InspectCurrentGrantRequest {};
        let bytes = dispatch_request(
            &mut state,
            &request(
                "TokenService",
                "InspectCurrentGrant",
                encode_request(&inspect),
            ),
            None,
        );
        let inspected =
            api::InspectCurrentGrantResponse::decode(decode_response(&bytes).payload.as_slice())
                .expect("inspect payload");
        assert!(inspected.grants.is_empty());
    }

    #[test]
    fn open_listener_validates_the_registration() {
        let (mut state, _tx) = test_state();
        let register = api::RegisterApplicationRequest {
            application_name: "notes".into(),
            requested_protocol_ids: vec!["org.umc.notes/1".into()],
            ..Default::default()
        };
        dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "RegisterApplication",
                encode_request(&register),
            ),
            None,
        );

        // A matching protocol id binds the listener: the v1 listener IS the
        // app registration, which inbound stream dispatch already honors.
        let mut open = api::OpenListenerRequest {
            application_handle: Some(api::OpaqueHandle {
                value: b"org.umc.notes/1".to_vec(),
            }),
            protocol_id: "org.umc.notes/1".into(),
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request("ApplicationService", "OpenListener", encode_request(&open)),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let opened = api::OpenListenerResponse::decode(response.payload.as_slice())
            .expect("payload")
            .listener_handle
            .expect("handle");
        assert_eq!(opened.value, b"org.umc.notes/1");

        // An unregistered app handle is NotFound; a protocol mismatch is
        // InvalidArgument.
        let mut foreign = open.clone();
        foreign.application_handle = Some(api::OpaqueHandle {
            value: b"org.umc.none/1".to_vec(),
        });
        let bytes = dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "OpenListener",
                encode_request(&foreign),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
        open.protocol_id = "org.umc.other/1".into();
        let bytes = dispatch_request(
            &mut state,
            &request("ApplicationService", "OpenListener", encode_request(&open)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
    }

    #[test]
    fn application_data_plane_methods_are_unimplemented_with_reason() {
        let (mut state, _tx) = test_state();
        // The data-plane methods have no v1 backing (no server-side dial
        // initiator, no pending-session queue, no per-app stream or
        // datagram handles, no bound-session model): each is Unimplemented
        // with an explicit reason so clients can tell the gap from a typo.
        for method in [
            "CloseListener",
            "Connect",
            "AcceptIncomingSession",
            "RejectIncomingSession",
            "OpenStream",
            "AcceptStream",
            "RejectStream",
            "ReadStream",
            "WriteStream",
            "CloseStreamSend",
            "ResetStream",
            "StopStream",
            "SendDatagram",
            "ReceiveDatagram",
        ] {
            let bytes = dispatch_request(
                &mut state,
                &request("ApplicationService", method, vec![]),
                None,
            );
            let response = decode_response(&bytes);
            assert_eq!(
                response.status.as_ref().unwrap().code,
                api::StatusCode::Unimplemented as i32,
                "{method} must be Unimplemented"
            );
            assert!(
                !response.status.as_ref().unwrap().message.is_empty(),
                "{method} must carry the reason"
            );
        }
    }

    #[allow(clippy::too_many_lines)] // one bundle lifecycle: create, get (3 chunk shapes), delete
    #[test]
    fn bundle_get_and_delete_round_trip() {
        let (mut state, _tx) = test_state();
        let create = api::CreateBundleRequest {
            application_handle: Some(api::OpaqueHandle {
                value: b"org.umc.notes/1".to_vec(),
            }),
            destination_hint: b"peer-hint".to_vec(),
            priority: 1,
            payload_chunk: b"hello-bundle".to_vec(),
            payload_complete: true,
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request("BundleService", "CreateBundle", encode_request(&create)),
            None,
        );
        let created = api::CreateBundleResponse::decode(decode_response(&bytes).payload.as_slice())
            .expect("payload")
            .bundle
            .expect("bundle");

        // GetBundle without payload: the summary only.
        let get = api::GetBundleRequest {
            bundle_id: created.bundle_id.clone(),
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request("BundleService", "GetBundle", encode_request(&get)),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let got = api::GetBundleResponse::decode(response.payload.as_slice()).expect("payload");
        let summary = got.bundle.expect("summary");
        assert_eq!(summary.payload_size, 12);
        assert!(
            got.payload_chunk.is_empty(),
            "no payload without include_payload"
        );
        assert!(!got.payload_eof);

        // GetBundle with the payload, chunked by offset/length.
        let get = api::GetBundleRequest {
            bundle_id: created.bundle_id.clone(),
            include_payload: true,
            payload_offset: 0,
            payload_length: 6,
        };
        let bytes = dispatch_request(
            &mut state,
            &request("BundleService", "GetBundle", encode_request(&get)),
            None,
        );
        let got = api::GetBundleResponse::decode(decode_response(&bytes).payload.as_slice())
            .expect("payload");
        assert_eq!(got.payload_chunk, b"hello-");
        assert!(!got.payload_eof, "offset 0 + 6 bytes of 12 is not the end");

        // The final chunk sets payload_eof.
        let get = api::GetBundleRequest {
            bundle_id: created.bundle_id.clone(),
            include_payload: true,
            payload_offset: 11,
            payload_length: 64,
        };
        let bytes = dispatch_request(
            &mut state,
            &request("BundleService", "GetBundle", encode_request(&get)),
            None,
        );
        let got = api::GetBundleResponse::decode(decode_response(&bytes).payload.as_slice())
            .expect("payload");
        assert_eq!(got.payload_chunk, b"e");
        assert!(got.payload_eof);

        // Unknown id is NotFound.
        let get = api::GetBundleRequest {
            bundle_id: vec![0u8; 32],
            include_payload: false,
            payload_offset: 0,
            payload_length: 0,
        };
        let bytes = dispatch_request(
            &mut state,
            &request("BundleService", "GetBundle", encode_request(&get)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );

        // DeleteBundle removes the record; a second delete is NotFound.
        let delete = api::DeleteBundleRequest {
            bundle_id: created.bundle_id.clone(),
            reason: "no longer needed".into(),
        };
        let bytes = dispatch_request(
            &mut state,
            &request("BundleService", "DeleteBundle", encode_request(&delete)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );
        assert!(state
            .bundle
            .find(&<[u8; 32]>::try_from(created.bundle_id.as_slice()).unwrap())
            .is_none());
        let bytes = dispatch_request(
            &mut state,
            &request("BundleService", "DeleteBundle", encode_request(&delete)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
    }

    #[test]
    fn relay_status_reports_limits_and_circuit_counts() {
        let (mut state, _tx) = test_state();
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "GetRelayStatus", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let status = api::GetRelayStatusResponse::decode(response.payload.as_slice())
            .expect("payload")
            .status
            .expect("status");
        // The v1 default limits: community relay with per-peer cap 4.
        assert_eq!(
            status.policy.as_ref().unwrap().mode,
            api::RelayMode::Community as i32
        );
        assert_eq!(status.policy.as_ref().unwrap().maximum_circuits_per_peer, 4);
        assert_eq!(status.active_circuits, 0);
        assert_eq!(status.bytes_forwarded, 0);

        // A live circuit moves the count.
        let open = OpenCircuitRequest {
            requested_lifetime_ms: 600_000,
            requested_byte_quota: 1_048_576,
            flags: 0,
            bidirectional: true,
            private_handling: false,
            peer_circuits: 0,
        };
        dispatch_request(
            &mut state,
            &request("RelayService", "OpenCircuit", encode_request(&open)),
            None,
        );
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "GetRelayStatus", vec![]),
            None,
        );
        let status =
            api::GetRelayStatusResponse::decode(decode_response(&bytes).payload.as_slice())
                .expect("payload")
                .status
                .expect("status");
        assert_eq!(status.active_circuits, 1);
        assert_eq!(status.opening_circuits, 1);
    }

    #[test]
    fn update_relay_policy_mutates_limits_and_blocks_new_circuits() {
        let (mut state, _tx) = test_state();
        let update = api::UpdateRelayPolicyRequest {
            policy: Some(api::RelayPolicy {
                mode: api::RelayMode::Disabled as i32,
                maximum_circuits_per_peer: 2,
                maximum_bytes_per_circuit: 1 << 20,
                maximum_lifetime_ms: 60_000,
                ..Default::default()
            }),
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "UpdateRelayPolicy", encode_request(&update)),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let echoed = api::UpdateRelayPolicyResponse::decode(response.payload.as_slice())
            .expect("payload")
            .policy
            .expect("policy");
        assert_eq!(echoed.mode, api::RelayMode::Disabled as i32);
        assert_eq!(echoed.maximum_circuits_per_peer, 2);

        // The limits mutated in place; a Disabled relay refuses opens.
        assert_eq!(state.relay.limits.max_circuits_per_peer, 2);
        assert_eq!(state.relay.limits.max_lifetime_ms, 60_000);
        let open = OpenCircuitRequest {
            requested_lifetime_ms: 600_000,
            requested_byte_quota: 1_048_576,
            flags: 0,
            bidirectional: true,
            private_handling: false,
            peer_circuits: 0,
        };
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "OpenCircuit", encode_request(&open)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::FailedPrecondition as i32
        );
    }

    #[test]
    fn list_relay_circuits_snapshots_redacted() {
        let (mut state, _tx) = test_state();
        let open = OpenCircuitRequest {
            requested_lifetime_ms: 600_000,
            requested_byte_quota: 1_048_576,
            flags: 0,
            bidirectional: true,
            private_handling: false,
            peer_circuits: 0,
        };
        // Open with an owner peer directly so the redaction is observable
        // (the control open path carries no owner).
        let peer = [7u8; 32];
        let granted = state
            .relay
            .open_circuit(
                &CircuitOpenRequest {
                    peer_circuits: 0,
                    requested_lifetime_ms: open.requested_lifetime_ms,
                    requested_byte_quota: open.requested_byte_quota,
                    flags: 0,
                    bidirectional: true,
                    private_handling: false,
                    destination_hint: b"dest-peer".to_vec(),
                },
                peer.to_vec(),
                crate::state::wall_now(),
            )
            .expect("open");

        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "ListRelayCircuits", vec![]),
            None,
        );
        let response = decode_response(&bytes);
        assert_eq!(
            response.status.as_ref().unwrap().code,
            api::StatusCode::Ok as i32
        );
        let listing =
            api::ListRelayCircuitsResponse::decode(response.payload.as_slice()).expect("payload");
        assert_eq!(listing.circuits.len(), 1);
        assert_eq!(listing.page.as_ref().unwrap().total_size_hint, 1);
        let circuit = &listing.circuits[0];
        assert_eq!(
            circuit.circuit_handle.as_ref().unwrap().value,
            granted.circuit_id.to_be_bytes()
        );
        assert_eq!(circuit.state, "opening");
        assert_eq!(circuit.granted_byte_quota, 1_048_576);
        assert_eq!(circuit.accepted_bytes, 0);
        // The owner peer is redacted: first 4 bytes kept, the rest zeroed.
        let mut redacted = [7u8; 32];
        redacted[4..].fill(0);
        assert_eq!(circuit.redacted_upstream_peer, redacted);
    }

    #[test]
    fn close_relay_circuit_via_handle() {
        let (mut state, _tx) = test_state();
        let open = OpenCircuitRequest {
            requested_lifetime_ms: 600_000,
            requested_byte_quota: 1_048_576,
            flags: 0,
            bidirectional: true,
            private_handling: false,
            peer_circuits: 0,
        };
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "OpenCircuit", encode_request(&open)),
            None,
        );
        let granted = OpenCircuitResponse::decode(decode_response(&bytes).payload.as_slice())
            .expect("payload");
        assert_eq!(state.relay.circuit_count(), 1);

        // The circuit handle is the 8-byte BE circuit id (the same value
        // OpenCircuit returns).
        let close = api::CloseRelayCircuitRequest {
            circuit_handle: Some(api::OpaqueHandle {
                value: granted.circuit_id.to_be_bytes().to_vec(),
            }),
            reason: "done".into(),
        };
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "CloseRelayCircuit", encode_request(&close)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );
        // The v1 close enters the CLOSING drain (relay.md §9.5): the circuit
        // leaves the opening/active pool but is still a live registry entry
        // until the drain completes.
        assert_eq!(state.relay.circuit_count(), 1);
        let snap = state.relay.snapshot().into_iter().next().expect("circuit");
        assert_eq!(
            snap.circuit.state,
            umc_relay::circuit::CircuitState::Closing
        );

        // Closing an already-closing circuit is idempotent Ok; an unknown
        // circuit id is NotFound and a malformed handle is InvalidArgument.
        let bytes = dispatch_request(
            &mut state,
            &request("RelayService", "CloseRelayCircuit", encode_request(&close)),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::Ok as i32
        );
        let unknown = api::CloseRelayCircuitRequest {
            circuit_handle: Some(api::OpaqueHandle {
                value: 999u64.to_be_bytes().to_vec(),
            }),
            ..Default::default()
        };
        let bytes = dispatch_request(
            &mut state,
            &request(
                "RelayService",
                "CloseRelayCircuit",
                encode_request(&unknown),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::NotFound as i32
        );
        let malformed = api::CloseRelayCircuitRequest {
            circuit_handle: Some(api::OpaqueHandle {
                value: b"short".to_vec(),
            }),
            reason: String::new(),
        };
        let bytes = dispatch_request(
            &mut state,
            &request(
                "RelayService",
                "CloseRelayCircuit",
                encode_request(&malformed),
            ),
            None,
        );
        assert_eq!(
            decode_response(&bytes).status.unwrap().code,
            api::StatusCode::InvalidArgument as i32
        );
    }

    #[test]
    fn application_requests_count_per_service() {
        let (mut state, _tx) = test_state();
        dispatch_request(
            &mut state,
            &request(
                "ApplicationService",
                "RegisterApplication",
                encode_request(&api::RegisterApplicationRequest {
                    application_name: "notes".into(),
                    requested_protocol_ids: vec!["org.umc.notes/1".into()],
                    ..Default::default()
                }),
            ),
            None,
        );
        assert_eq!(
            state
                .metrics
                .get(crate::state::metric_names::CONTROL_REQUESTS_APP),
            Some(1)
        );
    }
}
