//! Control-envelope transport state and handshake framing.
//!
//! This module owns the per-connection protocol state machine. Service
//! implementations remain in `server.rs` for now, but the transport no
//! longer needs to know their internal state: it calls the server's narrow
//! dispatch/response boundary.

use crate::cancellation::CancellationHandle;
use crate::control_authorization::{authorize_live_request_with_peer, control_principal_id};
use crate::control_events::acknowledge_event;
use crate::runtime_adapters::OsEntropy;
use crate::server::{
    dispatch_connection_request_with_cancellation, request_validation_status, response_envelope,
    DEFAULT_ENVELOPE_MAX,
};
use crate::state::{wall_now, RuntimeState};
use blake2::{Blake2s256, Digest};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use umc_control::conn::{SequenceTracker, API_VERSION_MAJOR, API_VERSION_MINOR};
use umc_control::proto::umc::api::v1 as api;
use umc_crypto::aead::PacketKeys;
use umc_storage::store::{Namespace, Store};
use umc_types::runtime::EntropySource;

const MAX_CLIENT_NAME_BYTES: usize = 128;
const CLIENT_INSTANCE_ID_BYTES: usize = 16;
const MAX_REQUESTED_FEATURES: usize = 64;
const MAX_FEATURE_NAME_BYTES: usize = 128;
const MIN_NEGOTIATED_ENVELOPE: usize = 1024;

/// Control feature identifiers implemented by this daemon. These names are
/// local API capabilities, not peer-protocol extensions; a client only gets a
/// feature back when it explicitly requested it.
const SUPPORTED_FEATURES: &[&str] = &[
    "control.events-v1",
    "control.idempotency-v1",
    "control.page-tokens-v1",
];

/// Per-connection control protocol state (control-api.md §6-7): the
/// credential presented at hello, the per-connection envelope sequence
/// tracker, the draining flag set by a peer `GoAway`, and the bounded
/// idempotency replay cache. Live request workers may run concurrently while
/// this state remains serialized at the connection boundary.
#[derive(Debug)]
pub(crate) struct ConnectionState {
    /// Set only after the Unix listener validates `SO_PEERCRED`. In-process
    /// unit tests model the already-authenticated local socket; production
    /// construction uses `authenticated_peer` explicitly.
    pub(crate) os_peer_authenticated: bool,
    pub(crate) presented_token: Option<Vec<u8>>,
    pub(crate) hello_received: bool,
    pub(crate) client_name: String,
    pub(crate) client_instance_id: Vec<u8>,
    pub(crate) connection_id: Vec<u8>,
    pub(crate) negotiated_envelope_max: usize,
    pub(crate) sequences: SequenceTracker,
    pub(crate) draining: bool,
    pub(crate) subscriptions: HashMap<u64, api::EventFilter>,
    pub(crate) next_server_sequence: u64,
}

impl ConnectionState {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            // Direct dispatcher tests historically model a same-user local
            // connection. The production listener uses `authenticated_peer`
            // after it has captured the real peer credential.
            os_peer_authenticated: cfg!(test),
            presented_token: None,
            hello_received: false,
            client_name: String::new(),
            client_instance_id: Vec::new(),
            connection_id: Vec::new(),
            negotiated_envelope_max: DEFAULT_ENVELOPE_MAX,
            sequences: SequenceTracker::new(),
            draining: false,
            subscriptions: HashMap::new(),
            next_server_sequence: 1,
        }
    }

    #[must_use]
    pub(crate) fn authenticated_peer() -> Self {
        let mut state = Self::new();
        state.os_peer_authenticated = true;
        state
    }

    pub(crate) fn next_server_sequence(&mut self) -> u64 {
        let sequence = self.next_server_sequence;
        self.next_server_sequence = self.next_server_sequence.saturating_add(1);
        sequence
    }
}

/// Bounded per-connection idempotency replay cache (control-api.md §18):
/// `(principal-or-connection, service, method, idempotency_key)` → stored
/// response bytes, 24-hour TTL, FIFO eviction at 1,024 entries. The cache is
/// owned by the daemon runtime rather than one connection, so reconnects
/// cannot repeat a mutation under the same authenticated principal. OS-peer
/// local clients use their connection ID as the scope and therefore do not
/// share replay state. A key reused with a different payload returns an explicit
/// idempotency conflict.
type IdempotencyKey = (Vec<u8>, String, String, Vec<u8>);

#[derive(Debug, Default)]
pub(crate) struct IdempotencyCache {
    entries: HashMap<IdempotencyKey, IdempotencyEntry>,
    order: VecDeque<IdempotencyKey>,
}

#[derive(Debug)]
struct IdempotencyEntry {
    response: Vec<u8>,
    payload_digest: [u8; 32],
    inserted_at_ms: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IdempotencyLookup {
    Miss,
    Replay(Vec<u8>),
    Conflict,
}

pub(crate) const IDEMPOTENCY_TTL_MS: u64 = 24 * 60 * 60 * 1000;
pub(crate) const IDEMPOTENCY_CACHE_CAP: usize = 1_024;
const IDEMPOTENCY_STORAGE_PREFIX: &[u8] = b"idempotency/";
const IDEMPOTENCY_STORAGE_AAD: &[u8] = b"UMC-IDEMPOTENCY-V1";

#[derive(Debug, Serialize, Deserialize)]
struct PersistedIdempotencyEntry {
    scope: Vec<u8>,
    service: String,
    method: String,
    idempotency_key: Vec<u8>,
    response: Vec<u8>,
    payload_digest: Vec<u8>,
    inserted_at_ms: u64,
}

impl IdempotencyCache {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Store `response` for `key` stamped at `now_ms`; re-keying an existing
    /// entry refreshes it, otherwise the oldest entry is evicted once the FIFO
    /// cap is exceeded.
    pub(crate) fn insert(
        &mut self,
        key: IdempotencyKey,
        response: Vec<u8>,
        payload: &[u8],
        now_ms: u64,
    ) {
        let payload_digest = Blake2s256::digest(payload).into();
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.response = response;
            entry.payload_digest = payload_digest;
            entry.inserted_at_ms = now_ms;
            return;
        }
        self.entries.insert(
            key.clone(),
            IdempotencyEntry {
                response,
                payload_digest,
                inserted_at_ms: now_ms,
            },
        );
        self.order.push_back(key);
        while self.order.len() > IDEMPOTENCY_CACHE_CAP {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    /// Restore encrypted replay entries from the daemon API namespace. A
    /// ticket-key change makes old entries undecryptable and they are safely
    /// ignored. Expired or malformed entries never enter the live cache.
    pub(crate) fn restore(store: &dyn Store, ticket_key: &[u8; 32], now_ms: u64) -> Self {
        let mut cache = Self::new();
        let Ok(entries) = store.scan(Namespace::Api) else {
            return cache;
        };
        let Ok(keys) = PacketKeys::from_traffic_secret(ticket_key) else {
            return cache;
        };
        for entry in entries {
            if !entry.key.starts_with(IDEMPOTENCY_STORAGE_PREFIX)
                || entry.value.len() < std::mem::size_of::<u64>() + umc_crypto::aead::TAG_LEN
            {
                continue;
            }
            let Ok(packet_number_bytes) = <[u8; 8]>::try_from(&entry.value[..8]) else {
                continue;
            };
            let packet_number = u64::from_be_bytes(packet_number_bytes);
            let aad = storage_aad(&entry.key);
            let Ok(plaintext) = keys.open(packet_number, &aad, &entry.value[8..]) else {
                continue;
            };
            let Ok(persisted) = serde_json::from_slice::<PersistedIdempotencyEntry>(&plaintext)
            else {
                continue;
            };
            if now_ms >= persisted.inserted_at_ms.saturating_add(IDEMPOTENCY_TTL_MS)
                || persisted.payload_digest.len() != 32
            {
                let _ = store.delete(Namespace::Api, &entry.key);
                continue;
            }
            let key = (
                persisted.scope,
                persisted.service,
                persisted.method,
                persisted.idempotency_key,
            );
            let payload_digest = persisted.payload_digest;
            cache.insert(
                key.clone(),
                persisted.response,
                &[],
                persisted.inserted_at_ms,
            );
            if let Some(entry) = cache.entries.get_mut(&key) {
                entry.payload_digest.copy_from_slice(&payload_digest);
            }
        }
        cache
    }

    /// Insert a replay entry and persist an encrypted copy. The response is
    /// sealed with the stable ticket key; storage failures leave the in-memory
    /// cache authoritative but are returned for an audit log.
    pub(crate) fn insert_persisted(
        &mut self,
        store: &dyn Store,
        ticket_key: &[u8; 32],
        key: &IdempotencyKey,
        response: Vec<u8>,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(), String> {
        let evicted = (!self.entries.contains_key(key)
            && self.order.len() >= IDEMPOTENCY_CACHE_CAP)
            .then(|| self.order.front().cloned())
            .flatten();
        self.insert(key.clone(), response, payload, now_ms);
        if let Some(evicted) = evicted {
            let _ = store.delete(Namespace::Api, &storage_key(&evicted));
        }
        let entry = self
            .entries
            .get(key)
            .ok_or_else(|| "cache insert lost".to_string())?;
        let persisted = PersistedIdempotencyEntry {
            scope: key.0.clone(),
            service: key.1.clone(),
            method: key.2.clone(),
            idempotency_key: key.3.clone(),
            response: entry.response.clone(),
            payload_digest: entry.payload_digest.to_vec(),
            inserted_at_ms: entry.inserted_at_ms,
        };
        let plaintext = serde_json::to_vec(&persisted).map_err(|error| error.to_string())?;
        let keys = PacketKeys::from_traffic_secret(ticket_key)
            .map_err(|error| format!("idempotency keys: {error:?}"))?;
        let storage_key = storage_key(key);
        let mut packet_number_bytes = [0u8; 8];
        OsEntropy.fill(&mut packet_number_bytes);
        let packet_number = u64::from_be_bytes(packet_number_bytes);
        let ciphertext = keys
            .seal(packet_number, &storage_aad(&storage_key), &plaintext)
            .map_err(|error| format!("idempotency seal: {error:?}"))?;
        let mut value = packet_number_bytes.to_vec();
        value.extend_from_slice(&ciphertext);
        store
            .put(Namespace::Api, &storage_key, &value)
            .map_err(|error| format!("idempotency store: {error:?}"))
    }

    /// The stored bytes for `key` when it is fresh at `now_ms`.
    pub(crate) fn get(
        &self,
        key: &IdempotencyKey,
        payload: &[u8],
        now_ms: u64,
    ) -> IdempotencyLookup {
        let Some(entry) = self.entries.get(key) else {
            return IdempotencyLookup::Miss;
        };
        if now_ms >= entry.inserted_at_ms.saturating_add(IDEMPOTENCY_TTL_MS) {
            return IdempotencyLookup::Miss;
        }
        let digest: [u8; 32] = Blake2s256::digest(payload).into();
        if digest == entry.payload_digest {
            IdempotencyLookup::Replay(entry.response.clone())
        } else {
            IdempotencyLookup::Conflict
        }
    }
}

fn storage_key(key: &IdempotencyKey) -> Vec<u8> {
    let mut canonical = Vec::new();
    for part in [
        key.0.as_slice(),
        key.1.as_bytes(),
        key.2.as_bytes(),
        key.3.as_slice(),
    ] {
        canonical.extend_from_slice(&(part.len() as u64).to_be_bytes());
        canonical.extend_from_slice(part);
    }
    let digest = Blake2s256::digest(canonical);
    let mut out = IDEMPOTENCY_STORAGE_PREFIX.to_vec();
    out.extend_from_slice(&digest);
    out
}

fn storage_aad(key: &[u8]) -> Vec<u8> {
    let mut aad = IDEMPOTENCY_STORAGE_AAD.to_vec();
    aad.extend_from_slice(key);
    aad
}

/// Rebind a cached response to the request ID of the replaying call. The
/// cached status/payload is stable, but response correlation is per request
/// and must not leak the ID from an earlier connection.
fn rebind_response_request_id(stored: &[u8], request_id: u64) -> Vec<u8> {
    let Ok(mut envelope) = api::Envelope::decode(stored) else {
        return stored.to_vec();
    };
    let Some(api::envelope::Body::Response(response)) = envelope.body.as_mut() else {
        return stored.to_vec();
    };
    response.request_id = request_id;
    let mut rebound = Vec::with_capacity(stored.len());
    if envelope.encode(&mut rebound).is_ok() {
        rebound
    } else {
        stored.to_vec()
    }
}

/// Handle one decoded envelope on a connection. Returns the response bytes to
/// write back, or `None` when the envelope is dropped or produces no response.
#[allow(clippy::too_many_lines)]
pub(crate) fn handle_envelope(
    conn: &mut ConnectionState,
    state: &mut RuntimeState,
    envelope: api::Envelope,
) -> Option<Vec<u8>> {
    handle_envelope_inner(conn, state, envelope, None, true)
}

/// Variant for live workers whose reader already validated the envelope
/// sequence before handing the request to a concurrent dispatcher.
pub(crate) fn handle_envelope_after_sequence_with_cancellation(
    conn: &mut ConnectionState,
    state: &mut RuntimeState,
    envelope: api::Envelope,
    cancellation: Option<&CancellationHandle>,
) -> Option<Vec<u8>> {
    handle_envelope_inner(conn, state, envelope, cancellation, false)
}

#[allow(clippy::too_many_lines)]
fn handle_envelope_inner(
    conn: &mut ConnectionState,
    state: &mut RuntimeState,
    envelope: api::Envelope,
    cancellation: Option<&CancellationHandle>,
    observe_sequence: bool,
) -> Option<Vec<u8>> {
    if observe_sequence && conn.sequences.observe(envelope.sequence).is_err() {
        log::debug!(
            "[control] dropped envelope with sequence {}",
            envelope.sequence
        );
        conn.draining = true;
        return None;
    }
    match envelope.body {
        Some(api::envelope::Body::ClientHello(hello)) => {
            if conn.hello_received || conn.draining {
                conn.draining = true;
                return None;
            }
            conn.presented_token = hello_token(&hello);
            if let Some(response) = handle_hello(state, conn, &hello) {
                conn.hello_received = true;
                Some(response)
            } else {
                conn.presented_token = None;
                conn.draining = true;
                None
            }
        }
        Some(api::envelope::Body::Request(request)) => {
            if !conn.hello_received {
                log::debug!("[control] request received before client hello");
                conn.draining = true;
                return None;
            }
            if conn.draining {
                return Some(response_envelope(
                    &request,
                    api::StatusCode::Unavailable as i32,
                    None,
                ));
            }
            // Validate before consulting or populating the replay cache. This
            // keeps malformed keys and oversized payloads from becoming cache
            // entries and guarantees every live request observes the same
            // boundary limits, including replays.
            if let Some(code) = request_validation_status(&request) {
                return Some(response_envelope(&request, code, None));
            }
            // Replays still pass the current authorization/resource checks;
            // revocation or handle expiry must not be bypassed by a cached
            // success from earlier on this connection.
            if let Err(code) = authorize_live_request_with_peer(
                state,
                &request,
                conn.presented_token.as_deref(),
                conn.os_peer_authenticated,
            ) {
                return Some(response_envelope(&request, code, None));
            }
            if cancellation.is_some_and(CancellationHandle::is_cancelled) {
                return Some(response_envelope(
                    &request,
                    api::StatusCode::Cancelled as i32,
                    None,
                ));
            }
            if !request.idempotency_key.is_empty() {
                let principal_id =
                    control_principal_id(state, conn.presented_token.as_deref()).unwrap_or(0);
                let scope = if principal_id == 0 {
                    conn.connection_id.clone()
                } else {
                    principal_id.to_be_bytes().to_vec()
                };
                let key = (
                    scope,
                    request.service.clone(),
                    request.method.clone(),
                    request.idempotency_key.clone(),
                );
                let now_ms = wall_now().0;
                match state.idempotency.get(&key, &request.payload, now_ms) {
                    IdempotencyLookup::Replay(stored) => {
                        log::debug!(
                            "[control] idempotent replay for request {}",
                            request.request_id
                        );
                        return Some(rebind_response_request_id(&stored, request.request_id));
                    }
                    IdempotencyLookup::Conflict => {
                        log::debug!(
                            "[control] idempotency conflict for request {}",
                            request.request_id
                        );
                        return Some(response_envelope(
                            &request,
                            api::StatusCode::IdempotencyConflict as i32,
                            None,
                        ));
                    }
                    IdempotencyLookup::Miss => {}
                }
                let presented_token = conn.presented_token.clone();
                let response = dispatch_connection_request_with_cancellation(
                    conn,
                    state,
                    &request,
                    presented_token.as_deref(),
                    cancellation,
                );
                let store = state.store.clone();
                let ticket_key = state.ticket_key;
                if let Err(error) = state.idempotency.insert_persisted(
                    store.as_ref(),
                    &ticket_key,
                    &key,
                    response.clone(),
                    &request.payload,
                    now_ms,
                ) {
                    log::warn!("[control] idempotency persistence failed: {error}");
                }
                return Some(response);
            }
            let presented_token = conn.presented_token.clone();
            Some(dispatch_connection_request_with_cancellation(
                conn,
                state,
                &request,
                presented_token.as_deref(),
                cancellation,
            ))
        }
        Some(api::envelope::Body::Cancel(cancel)) => {
            if !conn.hello_received {
                conn.draining = true;
                return None;
            }
            // Direct/unit callers do not provide the live registry. The socket
            // reader handles cancellation through its in-flight table before
            // workers reach this compatibility path.
            log::debug!(
                "[control] cancellation ignored for request {}",
                cancel.request_id
            );
            None
        }
        Some(api::envelope::Body::EventAck(ack)) => {
            if !conn.hello_received {
                conn.draining = true;
                return None;
            }
            acknowledge_event(state, conn, &ack);
            None
        }
        Some(api::envelope::Body::GoAway(go_away)) => {
            if !conn.hello_received {
                conn.draining = true;
                return None;
            }
            log::info!(
                "[control] go-away received (reason {}): draining",
                go_away.reason
            );
            conn.draining = true;
            None
        }
        _ => {
            if !conn.hello_received {
                conn.draining = true;
            }
            None
        }
    }
}

fn hello_token(hello: &api::ClientHello) -> Option<Vec<u8>> {
    match &hello.authentication.as_ref()?.method {
        Some(api::client_authentication::Method::Development(auth)) => Some(auth.token.clone()),
        Some(api::client_authentication::Method::Bearer(auth)) => Some(auth.token.clone()),
        Some(api::client_authentication::Method::Combined(auth)) => Some(auth.bearer_token.clone()),
        _ => None,
    }
}

pub(crate) fn handle_hello(
    state: &RuntimeState,
    conn: &mut ConnectionState,
    hello: &api::ClientHello,
) -> Option<Vec<u8>> {
    if !conn.os_peer_authenticated {
        // The socket listener normally rejects this before a hello is read.
        // Keep the transport state machine fail-closed if another local
        // transport is added later or a test constructs an untrusted state.
        return None;
    }
    if hello.client_name.len() > MAX_CLIENT_NAME_BYTES {
        return None;
    }
    if !hello.client_instance_id.is_empty()
        && hello.client_instance_id.len() != CLIENT_INSTANCE_ID_BYTES
    {
        return None;
    }
    let enabled_features = negotiate_features(&hello.requested_features)?;
    let negotiated_envelope_max = negotiate_envelope_size(hello.requested_envelope_size)?;
    let selected_version = if hello.supported_versions.is_empty() {
        // Empty is retained for protocol-focused legacy fixtures. Real
        // clients should always send the supported-version list.
        api::ApiVersion {
            major: API_VERSION_MAJOR,
            minor: API_VERSION_MINOR,
        }
    } else {
        *hello.supported_versions.iter().find(|version| {
            version.major == API_VERSION_MAJOR && version.minor == API_VERSION_MINOR
        })?
    };
    if conn.connection_id.is_empty() {
        conn.connection_id = vec![0u8; 16];
        OsEntropy.fill(&mut conn.connection_id);
    }
    let presented_token = conn.presented_token.as_deref();
    let authenticated_principal = control_principal_id(state, presented_token);
    let principal_id = match authenticated_principal {
        Some(principal) if principal != 0 => principal.to_be_bytes().to_vec(),
        None if presented_token.is_none() && conn.os_peer_authenticated => {
            // Principal zero is reserved for the transport-bound local
            // operator and can never be allocated to a bearer token.
            0u64.to_be_bytes().to_vec()
        }
        _ => Vec::new(),
    };
    let granted_capabilities = authenticated_principal
        .and_then(|principal| state.token_grants.get(&principal).cloned())
        .unwrap_or_default();
    let server_hello = api::ServerHello {
        selected_version: Some(selected_version),
        server_instance_id: state.server_instance_id.to_vec(),
        node_state: api::NodeLifecycleState::Running as i32,
        connection_id: conn.connection_id.clone(),
        principal_id,
        granted_capabilities,
        negotiated_envelope_size: u32::try_from(negotiated_envelope_max).expect("fits u32"),
        enabled_features,
        limits: Some(api::ConnectionLimits {
            maximum_envelope_size: u32::try_from(DEFAULT_ENVELOPE_MAX).expect("fits u32"),
            maximum_concurrent_requests: 1,
            maximum_queued_requests: 0,
            maximum_event_streams: u32::try_from(umc_control::events::MAX_EVENT_STREAMS_PER_CLIENT)
                .expect("fits u32"),
            maximum_event_backlog: 100,
            maximum_event_backlog_bytes: 1 << 20,
        }),
    };
    conn.client_name.clone_from(&hello.client_name);
    conn.client_instance_id
        .clone_from(&hello.client_instance_id);
    conn.negotiated_envelope_max = negotiated_envelope_max;
    let envelope = api::Envelope {
        api_version: Some(api::ApiVersion {
            major: API_VERSION_MAJOR,
            minor: API_VERSION_MINOR,
        }),
        sequence: 1,
        body: Some(api::envelope::Body::ServerHello(server_hello)),
    };
    let mut out = Vec::new();
    Message::encode(&envelope, &mut out).expect("encode");
    Some(out)
}

fn negotiate_features(requested: &[String]) -> Option<Vec<String>> {
    if requested.len() > MAX_REQUESTED_FEATURES {
        return None;
    }
    let mut enabled = Vec::new();
    for feature in requested {
        if feature.is_empty() || feature.len() > MAX_FEATURE_NAME_BYTES {
            return None;
        }
        if SUPPORTED_FEATURES.contains(&feature.as_str())
            && !enabled.iter().any(|enabled: &String| enabled == feature)
        {
            enabled.push(feature.clone());
        }
    }
    Some(enabled)
}

fn negotiate_envelope_size(requested: u32) -> Option<usize> {
    let requested = usize::try_from(requested).ok()?;
    if requested == 0 {
        return Some(DEFAULT_ENVELOPE_MAX);
    }
    if requested < MIN_NEGOTIATED_ENVELOPE {
        return None;
    }
    Some(requested.min(DEFAULT_ENVELOPE_MAX))
}
