//! Registry-backed `ApplicationService` control methods.
//!
//! The registration/listener surface and the bounded stream/datagram data
//! plane for established sessions are live in v1. Outbound `Connect` resolves
//! authenticated static-peer entries and hands the resulting transport into
//! the same session coordinator used by inbound links.

use crate::cancellation::CancellationHandle;
use crate::relay_link::RelayLink;
use crate::server::push_event;
use crate::runtime_adapters::OsEntropy;
use crate::state::{wall_now, ApplicationRegistration, RuntimeState};
use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use umc_carrier::types::OutboundPacket;
use umc_control::proto::umc::api::v1 as api;
use umc_routing::types::{RouteKey, RouteScope, RouteState};
use umc_session::datagram::Datagram;
use umc_types::runtime::EntropySource;

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticDialTarget {
    carrier: String,
    address: String,
    endpoint_id: [u8; 32],
}

fn is_application_capability(capability: api::Capability) -> bool {
    matches!(
        capability,
        api::Capability::ApplicationConnect
            | api::Capability::ApplicationListen
            | api::Capability::ApplicationStream
            | api::Capability::ApplicationDatagram
    )
}

fn requested_application_capabilities(
    requested: &[i32],
) -> Result<Vec<i32>, api::StatusCode> {
    let mut capabilities = requested
        .iter()
        .map(|raw| {
            let capability = api::Capability::try_from(*raw)
                .map_err(|_| api::StatusCode::InvalidArgument)?;
            if !is_application_capability(capability) {
                return Err(api::StatusCode::InvalidArgument);
            }
            Ok(capability as i32)
        })
        .collect::<Result<Vec<_>, _>>()?;
    capabilities.sort_unstable();
    capabilities.dedup();
    Ok(capabilities)
}

fn effective_application_grants(
    state: &RuntimeState,
    principal_id: u64,
    requested: &[i32],
) -> Result<Vec<api::CapabilityGrant>, api::StatusCode> {
    let requested = requested_application_capabilities(requested)?;
    // Principal zero is the authenticated same-user OS peer. Its authority
    // is local policy, not a bearer grant, so it must not manufacture grants
    // in the application response (control-api.md §11.1).
    if principal_id == 0 {
        return Ok(Vec::new());
    }
    let now_ms = wall_now().0;
    Ok(state
        .token_grants
        .get(&principal_id)
        .into_iter()
        .flatten()
        .filter_map(|grant| {
            let capability = api::Capability::try_from(grant.capability).ok()?;
            if !is_application_capability(capability)
                || grant.expires_at_unix_ms < 0
                || (grant.expires_at_unix_ms > 0
                    && u64::try_from(grant.expires_at_unix_ms)
                        .ok()
                        .is_some_and(|expires| now_ms >= expires))
                || (!requested.is_empty() && !requested.contains(&grant.capability))
            {
                return None;
            }
            Some(grant.clone())
        })
        .collect())
}

fn registration_response(
    handle: Vec<u8>,
    effective_grants: Vec<api::CapabilityGrant>,
    resume_token: Vec<u8>,
) -> (i32, Option<Vec<u8>>) {
    let response = api::RegisterApplicationResponse {
        application_handle: Some(api::OpaqueHandle { value: handle }),
        effective_grants,
        resume_token,
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn resolve_static_peer(
    config: &crate::config::NodeConfig,
    destination_hint: &[u8],
) -> Result<StaticDialTarget, String> {
    let endpoint_hint = <[u8; 32]>::try_from(destination_hint).ok();
    let address_hint = std::str::from_utf8(destination_hint).ok();
    config
        .static_peers
        .iter()
        .find_map(|peer| {
            let endpoint_id = crate::static_peers::parse_endpoint_id(&peer.endpoint_id).ok()?;
            let endpoint_matches = endpoint_hint.is_some_and(|hint| hint == endpoint_id);
            let address_matches = address_hint.is_some_and(|hint| hint == peer.address);
            (endpoint_matches || address_matches).then(|| StaticDialTarget {
                carrier: peer.carrier.clone(),
                address: peer.address.clone(),
                endpoint_id,
            })
        })
        .ok_or_else(|| "destination hint does not match a configured static peer".into())
}

async fn race_deadline_or_cancellation<T, F>(
    operation: F,
    remaining_ms: u64,
    cancellation: Option<CancellationHandle>,
) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
{
    let cancellation_wait = async move {
        if let Some(handle) = cancellation {
            handle.cancelled().await;
            Err("cancelled".to_string())
        } else {
            std::future::pending::<Result<T, String>>().await
        }
    };
    tokio::select! {
        result = tokio::time::timeout(Duration::from_millis(remaining_ms), operation) => {
            result.map_err(|_| "deadline exceeded".to_string())?
        }
        result = cancellation_wait => result,
    }
}

/// Refuse a static direct dial when the caller supplied a carrier allow-list.
/// A static peer is a concrete direct path, so selecting a carrier outside the
/// request's constraints would violate the connection policy before any
/// network work begins.
fn reject_disallowed_carrier(
    state: &mut RuntimeState,
    connect: &api::ConnectRequest,
    target: &StaticDialTarget,
) -> bool {
    let Some(route) = connect
        .policy
        .as_ref()
        .and_then(|policy| policy.route.as_ref())
    else {
        return false;
    };
    if route.allowed_carrier_types.is_empty()
        || route
            .allowed_carrier_types
            .iter()
            .any(|allowed| allowed == &target.carrier)
    {
        return false;
    }
    push_event(
        state,
        "carrier_policy_rejected",
        format!(
            "application connect carrier {} is outside the requested allow-list",
            target.carrier
        ),
    );
    true
}

fn resolve_connect_target(
    state: &mut RuntimeState,
    connect: &api::ConnectRequest,
    direct: bool,
) -> Result<StaticDialTarget, i32> {
    let target = resolve_static_peer(&state.config, &connect.destination_hint)
        .map_err(|_| api::StatusCode::NotFound as i32)?;
    if direct && reject_disallowed_carrier(state, connect, &target) {
        return Err(api::StatusCode::FailedPrecondition as i32);
    }
    if direct
        && (state.config.carrier_disabled(&target.carrier)
            || state.node.carrier(&target.carrier).is_none())
    {
        return Err(if state.config.carrier_disabled(&target.carrier) {
            api::StatusCode::FailedPrecondition as i32
        } else {
            api::StatusCode::NotFound as i32
        });
    }
    Ok(target)
}

fn relay_route_allowed(connect: &api::ConnectRequest) -> bool {
    connect
        .policy
        .as_ref()
        .and_then(|policy| policy.route.as_ref())
        .is_some_and(|route| {
            route.allow_relay
                && (route.allowed_carrier_types.is_empty()
                    || route
                        .allowed_carrier_types
                        .iter()
                        .any(|carrier| carrier == "ump.relay/1"))
        })
}

fn validate_connect_route_policy(connect: &api::ConnectRequest) -> Result<(), i32> {
    let Some(route) = connect
        .policy
        .as_ref()
        .and_then(|policy| policy.route.as_ref())
    else {
        return Ok(());
    };
    if api::RouteScope::try_from(route.scope).is_err()
        || api::TrustState::try_from(route.minimum_trust).is_err()
    {
        return Err(api::StatusCode::InvalidArgument as i32);
    }
    // Authenticated live sessions provide Observed evidence. Requiring a
    // stronger trust state must not silently downgrade to that evidence.
    if route.minimum_trust > api::TrustState::Observed as i32 {
        return Err(api::StatusCode::FailedPrecondition as i32);
    }
    Ok(())
}

fn route_scope(scope: i32) -> RouteScope {
    match scope {
        1 => RouteScope::LinkLocal,
        2 => RouteScope::LocalMesh,
        3 => RouteScope::Introduced,
        _ => RouteScope::General,
    }
}

fn decode_endpoint_label(label: &str) -> Option<Vec<u8>> {
    if label.len() != 64 {
        return None;
    }
    let mut endpoint = Vec::with_capacity(32);
    for pair in label.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        endpoint.push(u8::try_from((high << 4) | low).ok()?);
    }
    Some(endpoint)
}

fn endpoint_label(endpoint: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut label = String::with_capacity(endpoint.len() * 2);
    for byte in endpoint {
        let _ = write!(label, "{byte:02x}");
    }
    label
}

fn relay_peers_for_destination(
    state: &RuntimeState,
    destination: &[u8; 32],
    route: &api::RoutePolicy,
) -> Vec<Vec<u8>> {
    let scope = route_scope(route.scope);
    let now = state.node.clock.as_ref().now();
    // Route probes key destinations by the protocol hash. Keep the raw
    // endpoint-id lookup as a bounded compatibility fallback for pre-hash
    // cache entries created by older daemons and SDK callers.
    let mut records = Vec::new();
    for destination_hash in [
        crate::session_task::hash_destination(destination),
        *destination,
    ] {
        let key = RouteKey {
            destination_profile: 0,
            destination_hash,
            scope,
            policy_class: 0,
        };
        records.extend(state.routing.diverse_route_candidates(
            &key,
            now,
            umc_routing::cache::DEFAULT_CACHE_TARGET,
        ));
    }
    // This handoff constructs the carrier itself after selecting a live
    // authenticated next-hop session, so an allow-list containing the relay
    // carrier is concrete evidence rather than an unverifiable route claim.
    // Keep the generic validator strict for other carrier classes.
    let mut candidate_policy = route.clone();
    if candidate_policy
        .allowed_carrier_types
        .iter()
        .any(|carrier| carrier == "ump.relay/1")
    {
        candidate_policy.allowed_carrier_types.clear();
    }
    let mut peers = Vec::new();
    for record in records {
        if record.state != RouteState::Usable
            || !crate::server::route_candidate_eligible(
                state,
                &record,
                &candidate_policy,
                scope,
                true,
            )
        {
            continue;
        }
        let Some(next_hop) = decode_endpoint_label(&record.next_hop).or_else(|| {
            state
                .config
                .static_peers
                .iter()
                .find(|peer| peer.address == record.next_hop)
                .and_then(|peer| crate::static_peers::parse_endpoint_id(&peer.endpoint_id).ok())
                .map(|endpoint| endpoint.to_vec())
        }) else {
            continue;
        };
        if next_hop.as_slice() == destination || peers.iter().any(|peer| peer == &next_hop) {
            continue;
        }
        if state
            .bus
            .lock()
            .expect("session bus")
            .lookup(&next_hop)
            .is_some()
        {
            peers.push(next_hop);
        }
        if peers.len() >= umc_routing::cache::DEFAULT_CACHE_TARGET {
            break;
        }
    }
    peers
}

#[allow(dead_code)]
fn relay_peer_for_destination(
    state: &RuntimeState,
    destination: &[u8; 32],
    route: &api::RoutePolicy,
) -> Option<Vec<u8>> {
    relay_peers_for_destination(state, destination, route)
        .into_iter()
        .next()
}

fn mark_relay_route_failure(
    state: &mut RuntimeState,
    destination: &[u8; 32],
    route: &api::RoutePolicy,
    relay_peer: &[u8],
) {
    let scope = route_scope(route.scope);
    let now = state.node.clock.as_ref().now();
    for destination_hash in [
        crate::session_task::hash_destination(destination),
        *destination,
    ] {
        let key = RouteKey {
            destination_profile: 0,
            destination_hash,
            scope,
            policy_class: 0,
        };
        let label = if relay_peer.len() == 32 {
            endpoint_label(relay_peer)
        } else {
            String::from_utf8_lossy(relay_peer).into_owned()
        };
        if state.routing.mark_route_failure(&key, &label, now) {
            break;
        }
    }
}

fn connect_transport_blocking(
    state: &mut RuntimeState,
    target: &StaticDialTarget,
    deadline: umc_types::runtime::Instant,
    cancellation: Option<CancellationHandle>,
) -> Result<umc_core::node::ConnectedTransport, String> {
    let expected_endpoint_id = target.endpoint_id;
    let remaining_ms = deadline
        .duration_since(state.node.clock.as_ref().now())
        .as_millis();
    if remaining_ms == 0 {
        return Err("deadline exceeded".into());
    }
    let operation_deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(remaining_ms))
        .ok_or_else(|| "deadline exceeded".to_string())?;
    let future = state.node.connect_transport_with_deadline(
        &target.carrier,
        target.address.clone(),
        Some(expected_endpoint_id),
        operation_deadline,
    );
    let operation = async move {
        future.await.map_err(|error| match error {
            umc_core::node::NodeError::DeadlineExceeded => "deadline exceeded".into(),
            other => format!("connect: {other:?}"),
        })
    };
    let operation = race_deadline_or_cancellation(operation, remaining_ms, cancellation);
    let result = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            return Err("outbound connect requires a multi-thread runtime".into());
        }
        tokio::task::block_in_place(|| handle.block_on(operation))
    } else {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("connect runtime: {error}"))?;
        runtime.block_on(operation)
    };
    result
}

fn connect_transport_relay_blocking(
    state: &mut RuntimeState,
    target: &StaticDialTarget,
    relay_peer: Vec<u8>,
    deadline: umc_types::runtime::Instant,
    cancellation: Option<CancellationHandle>,
) -> Result<umc_core::node::ConnectedTransport, String> {
    let remaining_ms = deadline
        .duration_since(state.node.clock.as_ref().now())
        .as_millis();
    if remaining_ms == 0 {
        return Err("deadline exceeded".into());
    }
    let relay_session = state
        .bus
        .lock()
        .expect("session bus")
        .lookup(&relay_peer)
        .ok_or_else(|| "relay session unavailable".to_string())?;
    let mut circuit_bytes = [0u8; 8];
    umc_types::runtime::EntropySource::fill(state.node.entropy.as_ref(), &mut circuit_bytes);
    let circuit_id = (u64::from_be_bytes(circuit_bytes) & ((1u64 << 62) - 1)).max(1);
    let mut route_nonce = [0u8; 16];
    umc_types::runtime::EntropySource::fill(state.node.entropy.as_ref(), &mut route_nonce);
    let (link, incoming) = RelayLink::origin(
        state.bus.clone(),
        relay_peer,
        circuit_id,
        crate::session_task::privacy_route_token_with_nonce(&target.endpoint_id, route_nonce),
    );
    state
        .relay_endpoint_handoffs
        .insert((relay_session, circuit_id), incoming);
    let operation_deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(remaining_ms))
        .ok_or_else(|| "deadline exceeded".to_string())?;
    let future = state.node.connect_transport_over_link_with_deadline(
        "ump.relay/1",
        Box::new(link),
        Some(target.endpoint_id),
        operation_deadline,
    );
    let operation = async move {
        future.await.map_err(|error| match error {
            umc_core::node::NodeError::DeadlineExceeded => "deadline exceeded".into(),
            other => format!("connect: {other:?}"),
        })
    };
    let operation = race_deadline_or_cancellation(operation, remaining_ms, cancellation);
    let result = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            return Err("outbound connect requires a multi-thread runtime".into());
        }
        tokio::task::block_in_place(|| handle.block_on(operation))
    } else {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("connect runtime: {error}"))?;
        runtime.block_on(operation)
    };
    if result.is_err() {
        state
            .relay_endpoint_handoffs
            .remove(&(relay_session, circuit_id));
    }
    result
}

/// Connect an application using one of the daemon's authenticated static
/// peer entries. The request remains bounded by the carrier's dial/handshake
/// timeouts and returns a live session handle when registration succeeds.
#[allow(clippy::too_many_lines)]
pub(crate) fn connect(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
    deadline: umc_types::runtime::Instant,
    cancellation: Option<CancellationHandle>,
) -> (i32, Option<Vec<u8>>) {
    let Ok(connect) = api::ConnectRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let application = match owned_application(
        state,
        connect.application_handle.as_ref(),
        principal_id,
        connection_id,
    ) {
        Ok(application) => application,
        Err(code) => return (code, None),
    };
    if connect.protocol_id.is_empty()
        || !state
            .application_protocols
            .get(&application)
            .is_some_and(|protocols| {
                protocols
                    .iter()
                    .any(|protocol| protocol.as_slice() == connect.protocol_id.as_bytes())
            })
    {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    if let Err(status) = validate_connect_route_policy(&connect) {
        return (status, None);
    }
    let private_route = state
        .config
        .effective_privacy_profile()
        .includes(umc_core::privacy::PrivacyProfile::P2);
    if private_route && !relay_route_allowed(&connect) {
        push_event(
            state,
            "privacy_route_required",
            "P2/P3 application connect requires an explicit relay route policy".into(),
        );
        return (api::StatusCode::FailedPrecondition as i32, None);
    }
    let target = match resolve_connect_target(state, &connect, !private_route) {
        Ok(target) => target,
        Err(status) => return (status, None),
    };
    let Some(runtime) = state.self_arc.upgrade() else {
        return (api::StatusCode::Unavailable as i32, None);
    };
    let relay_policy = connect
        .policy
        .as_ref()
        .and_then(|policy| policy.route.as_ref());
    let relay_peers = if private_route {
        relay_policy.map_or_else(Vec::new, |route| {
            relay_peers_for_destination(state, &target.endpoint_id, route)
        })
    } else {
        Vec::new()
    };
    if private_route && relay_peers.is_empty() {
        push_event(
            state,
            "privacy_route_unavailable",
            "no authenticated relay session is available for the destination".into(),
        );
        return (api::StatusCode::Unavailable as i32, None);
    }
    let connection = match if private_route {
        let mut last_error = "no eligible relay route".to_string();
        let mut connected = None;
        for relay_peer in relay_peers {
            match connect_transport_relay_blocking(
                state,
                &target,
                relay_peer.clone(),
                deadline,
                cancellation.clone(),
            ) {
                Ok(connection) => {
                    connected = Some(connection);
                    break;
                }
                Err(error) if error == "deadline exceeded" || error == "cancelled" => {
                    return (
                        if error == "deadline exceeded" {
                            api::StatusCode::DeadlineExceeded as i32
                        } else {
                            api::StatusCode::Cancelled as i32
                        },
                        None,
                    );
                }
                Err(error) => {
                    last_error = error;
                    if let Some(route) = relay_policy {
                        mark_relay_route_failure(state, &target.endpoint_id, route, &relay_peer);
                    }
                }
            }
        }
        connected.ok_or(last_error)
    } else {
        connect_transport_blocking(state, &target, deadline, cancellation)
    } {
        Ok(connection) => connection,
        Err(error) if error == "deadline exceeded" => {
            return (api::StatusCode::DeadlineExceeded as i32, None);
        }
        Err(error) if error == "cancelled" => {
            return (api::StatusCode::Cancelled as i32, None);
        }
        Err(error) => {
            log::debug!("[application] outbound connect failed: {error}");
            return (api::StatusCode::Unavailable as i32, None);
        }
    };
    let session_id = match crate::register_session_locked(
        runtime,
        state,
        if private_route {
            "ump.relay/1"
        } else {
            &target.carrier
        },
        connection.link,
        connection.dcid,
        connection.secrets.client,
        connection.secrets.server,
        Some(connection.secrets.stateless_reset),
        None,
        connection.peer_endpoint_id,
        crate::state::wall_now(),
        state.config.effective_privacy_profile() as u8,
        umc_session::session::Role::Client,
    ) {
        Ok(session_id) => session_id,
        Err(error) => {
            log::debug!("[application] outbound session registration failed: {error}");
            return (api::StatusCode::Unavailable as i32, None);
        }
    };
    if state
        .application_data
        .bind_session_owned(
            session_id,
            connection_id.to_vec(),
            application,
            principal_id,
            false,
        )
        .is_err()
    {
        if let Some(entry) = state.sessions.lookup(session_id) {
            entry.task.abort();
        }
        return (api::StatusCode::Conflict as i32, None);
    }
    let response = api::ConnectResponse {
        session_handle: Some(api::OpaqueHandle {
            value: session_id.to_be_bytes().to_vec(),
        }),
        operation_handle: None,
        session: state.sessions.lookup(session_id).map(|entry| {
            crate::server::session_summary(
                session_id,
                &entry,
                crate::server::active_path_count(state, session_id),
            )
        }),
    };
    (api::StatusCode::Ok as i32, encode_payload(&response))
}

/// Register an application and all of its requested protocol identifiers.
#[allow(clippy::too_many_lines)]
pub(crate) fn register(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(register) = api::RegisterApplicationRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if register.application_name.is_empty() || register.requested_protocol_ids.is_empty() {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    if register.resumable && principal_id == 0 {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    if register.resumable && register.application_instance_id.len() != 16 {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let normalized_capabilities = match requested_application_capabilities(
        &register.requested_capabilities,
    ) {
        Ok(capabilities) => capabilities,
        Err(status) => return (status as i32, None),
    };
    let effective_grants = match effective_application_grants(
        state,
        principal_id,
        &normalized_capabilities,
    ) {
        Ok(grants) => grants,
        Err(status) => return (status as i32, None),
    };

    // Re-registration is the resumable-principal handshake. The bearer
    // principal and stable application instance id are the authenticated
    // lookup key; the opaque token is returned for client persistence and
    // audit, while the transport's ClientHello still authenticates the
    // principal before this method runs.
    if register.resumable {
        let existing = state
            .application_registrations
            .iter()
            .find_map(|(handle, metadata)| {
                (metadata.resumable
                    && metadata.application_instance_id == register.application_instance_id
                    && state.application_principals.get(handle) == Some(&principal_id))
                    .then(|| (handle.clone(), metadata.clone()))
            });
        if let Some((handle, metadata)) = existing {
            if state
                .application_connections
                .get(&handle)
                .is_some_and(|owner| !owner.is_empty() && owner.as_slice() != connection_id)
            {
                return (api::StatusCode::AlreadyExists as i32, None);
            }
            if metadata.application_name != register.application_name
                || metadata.requested_endpoint_ids != register.requested_endpoint_ids
                || metadata.requested_protocol_ids != register.requested_protocol_ids
                || metadata.requested_capabilities != normalized_capabilities
            {
                return (api::StatusCode::AlreadyExists as i32, None);
            }
            state
                .application_connections
                .insert(handle.clone(), connection_id.to_vec());
            if state
                .application_data
                .rebind_application(&handle, principal_id, connection_id)
                .is_err()
            {
                return (api::StatusCode::PermissionDenied as i32, None);
            }
            if let Some(registration) = state.application_registrations.get_mut(&handle) {
                registration.effective_grants.clone_from(&effective_grants);
            }
            push_event(state, "application_resumed", register.application_name);
            return registration_response(handle, effective_grants, metadata.resume_token);
        }
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
    state.application_principals.insert(
        register.requested_protocol_ids[0].as_bytes().to_vec(),
        principal_id,
    );
    state.application_connections.insert(
        register.requested_protocol_ids[0].as_bytes().to_vec(),
        connection_id.to_vec(),
    );
    let mut resume_token = Vec::new();
    if register.resumable {
        resume_token.resize(32, 0);
        OsEntropy.fill(&mut resume_token);
    }
    let handle = register.requested_protocol_ids[0].as_bytes().to_vec();
    state.application_registrations.insert(
        handle.clone(),
        ApplicationRegistration {
            application_name: register.application_name.clone(),
            application_instance_id: register.application_instance_id.clone(),
            requested_endpoint_ids: register.requested_endpoint_ids.clone(),
            requested_protocol_ids: register.requested_protocol_ids.clone(),
            requested_capabilities: normalized_capabilities,
            resumable: register.resumable,
            effective_grants: effective_grants.clone(),
            resume_token: resume_token.clone(),
        },
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
    registration_response(handle, effective_grants, resume_token)
}

/// Unregister an application and every protocol/channel belonging to it.
pub(crate) fn unregister(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(unregister) = api::UnregisterApplicationRequest::decode(request.payload.as_slice())
    else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = unregister.application_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let known = state.application_protocols.contains_key(&handle.value)
        || state.apps.lookup(&handle.value).is_some();
    if !known {
        return (api::StatusCode::NotFound as i32, None);
    }
    if !owns_handle(state, &handle.value, principal_id, connection_id) {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
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
    state.application_principals.remove(&handle.value);
    state.application_connections.remove(&handle.value);
    state.application_registrations.remove(&handle.value);
    state.application_listeners.remove(&handle.value);
    if unregister.close_owned_sessions {
        for session_id in state
            .application_data
            .session_ids_for_application(&handle.value)
        {
            if let Some(entry) = state.sessions.lookup(session_id) {
                entry.task.abort();
            }
        }
    }
    state.application_data.remove_application(&handle.value);
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

/// Validate the registration and return its protocol id as the listener handle.
pub(crate) fn open_listener(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(open) = api::OpenListenerRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = open.application_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if state.apps.lookup(&handle.value).is_none() {
        return (api::StatusCode::NotFound as i32, None);
    }
    if !owns_handle(state, &handle.value, principal_id, connection_id) {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    if !open.protocol_id.is_empty() && open.protocol_id.as_bytes() != handle.value.as_slice() {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let maximum_pending_sessions = open.policy.as_ref().map_or(
        crate::application_data::MAX_APPLICATION_PENDING_SESSIONS,
        |policy| usize::try_from(policy.maximum_pending_sessions).unwrap_or(usize::MAX),
    );
    if maximum_pending_sessions == 0 {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    if !state.application_listeners.insert(handle.value.clone()) {
        return (api::StatusCode::AlreadyExists as i32, None);
    }
    state.application_data.register_listener_with_limit(
        handle.value.clone(),
        handle.value.clone(),
        principal_id,
        connection_id.to_vec(),
        maximum_pending_sessions,
    );
    let response = api::OpenListenerResponse {
        listener_handle: Some(api::OpaqueHandle {
            value: handle.value,
        }),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// Close a listener without unregistering its owning application. The v1
/// listener handle is the application handle, so ownership and connection
/// generation checks are identical to the registration checks.
pub(crate) fn close_listener(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(close) = api::CloseListenerRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = close.listener_handle else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if !state.application_listeners.contains(&handle.value) {
        return (api::StatusCode::NotFound as i32, None);
    }
    if !owns_handle(state, &handle.value, principal_id, connection_id) {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    state.application_listeners.remove(&handle.value);
    state.application_data.remove_listener(&handle.value);
    push_event(
        state,
        "application_listener_closed",
        format!("listener {:?} closed", handle.value),
    );
    let mut payload = Vec::new();
    Message::encode(&api::CloseListenerResponse {}, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn session_id_from_handle(handle: Option<&api::OpaqueHandle>) -> Option<u64> {
    handle
        .and_then(|handle| <[u8; 8]>::try_from(handle.value.as_slice()).ok())
        .map(u64::from_be_bytes)
}

fn application_error_status(error: crate::application_data::ApplicationDataError) -> i32 {
    use crate::application_data::ApplicationDataError as E;
    match error {
        E::NotFound => api::StatusCode::NotFound as i32,
        E::PermissionDenied => api::StatusCode::PermissionDenied as i32,
        E::Pending => api::StatusCode::FailedPrecondition as i32,
        E::AlreadyAccepted => api::StatusCode::AlreadyExists as i32,
        E::QueueFull => api::StatusCode::ResourceExhausted as i32,
        E::InvalidArgument => api::StatusCode::InvalidArgument as i32,
        E::WouldBlock => api::StatusCode::Unavailable as i32,
    }
}

fn session_error_status(error: &umc_session::session::SessionError) -> i32 {
    use umc_session::session::SessionError as E;
    match error {
        E::StreamNotFound => api::StatusCode::NotFound as i32,
        E::StreamClosed | E::Stream(_) | E::AmplificationLimit => {
            api::StatusCode::FailedPrecondition as i32
        }
        E::StreamLimit | E::Flow(_) | E::Datagram(_) | E::CongestionLimited => {
            api::StatusCode::ResourceExhausted as i32
        }
        _ => api::StatusCode::Internal as i32,
    }
}

fn encode_payload<M: Message>(message: &M) -> Option<Vec<u8>> {
    let mut payload = Vec::new();
    message.encode(&mut payload).ok()?;
    Some(payload)
}

/// Build and synchronously send one protected application payload. The
/// session mutex is deliberately acquired with `try_lock`: control requests
/// must never block the wire reader while it is applying an inbound packet.
fn send_session_payload(
    state: &RuntimeState,
    control: &crate::session_manager::SessionControl,
    payload: &[u8],
) -> Result<(), i32> {
    let now = state.node.clock.as_ref().now();
    let mut session = control
        .session
        .try_lock()
        .map_err(|_| api::StatusCode::ResourceExhausted as i32)?;
    let packet = session
        .build_outbound(state.node.clock.as_ref(), now, payload)
        .map_err(|error| session_error_status(&error))?
        .ok_or(api::StatusCode::Unavailable as i32)?;
    session.touch(now);
    drop(session);
    control
        .link
        .send(OutboundPacket {
            bytes: packet,
            control: false,
            deadline_ms: None,
        })
        .map(|_| ())
        .map_err(|_| api::StatusCode::Unavailable as i32)
}

fn owned_application(
    state: &RuntimeState,
    handle: Option<&api::OpaqueHandle>,
    principal_id: u64,
    connection_id: &[u8],
) -> Result<Vec<u8>, i32> {
    let handle = handle.ok_or(api::StatusCode::InvalidArgument as i32)?;
    if state.apps.lookup(&handle.value).is_none() {
        return Err(api::StatusCode::NotFound as i32);
    }
    if !owns_handle(state, &handle.value, principal_id, connection_id) {
        return Err(api::StatusCode::PermissionDenied as i32);
    }
    Ok(handle.value.clone())
}

fn owned_session_control(
    state: &RuntimeState,
    session_id: u64,
) -> Result<Arc<crate::session_manager::SessionControl>, i32> {
    if state.sessions.lookup(session_id).is_none() {
        return Err(api::StatusCode::NotFound as i32);
    }
    state
        .session_controls
        .get(&session_id)
        .cloned()
        .ok_or(api::StatusCode::Unavailable as i32)
}

pub(crate) fn accept_incoming_session(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(accept) = api::AcceptIncomingSessionRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let application = match owned_application(
        state,
        accept.application_handle.as_ref(),
        principal_id,
        connection_id,
    ) {
        Ok(application) => application,
        Err(code) => return (code, None),
    };
    let Some(session_id) = session_id_from_handle(accept.pending_session_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some((owner, owner_connection, owner_application, _)) =
        state.application_data.session_owner(session_id)
    else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if owner != principal_id
        || owner_connection.as_slice() != connection_id
        || owner_application != application
    {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    match state
        .application_data
        .accept_session(session_id, principal_id, connection_id)
    {
        Ok(()) => {
            let response = api::AcceptIncomingSessionResponse {
                session_handle: Some(api::OpaqueHandle {
                    value: session_id.to_be_bytes().to_vec(),
                }),
                session: state.sessions.lookup(session_id).map(|entry| {
                    crate::server::session_summary(
                        session_id,
                        &entry,
                        crate::server::active_path_count(state, session_id),
                    )
                }),
            };
            (api::StatusCode::Ok as i32, encode_payload(&response))
        }
        Err(error) => (application_error_status(error), None),
    }
}

pub(crate) fn reject_incoming_session(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(reject) = api::RejectIncomingSessionRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(session_id) = session_id_from_handle(reject.pending_session_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some((owner, owner_connection, owner_application, _pending)) =
        state.application_data.session_owner(session_id)
    else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let Some(application) = reject.application_handle.as_ref() else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if !owns_handle(state, &application.value, principal_id, connection_id)
        || owner != principal_id
        || owner_connection.as_slice() != connection_id
        || owner_application != application.value
    {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    match state
        .application_data
        .reject_session(session_id, principal_id, connection_id)
    {
        Ok(()) => {
            if let Some(entry) = state.sessions.lookup(session_id) {
                entry.task.abort();
            }
            (
                api::StatusCode::Ok as i32,
                encode_payload(&api::RejectIncomingSessionResponse {}),
            )
        }
        Err(error) => (application_error_status(error), None),
    }
}

pub(crate) fn open_stream(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(open) = api::OpenStreamRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let application = match owned_application(
        state,
        open.application_handle.as_ref(),
        principal_id,
        connection_id,
    ) {
        Ok(application) => application,
        Err(code) => return (code, None),
    };
    let Some(session_id) = session_id_from_handle(open.session_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok(control) = owned_session_control(state, session_id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let protocol_id = state
        .application_protocols
        .get(&application)
        .and_then(|protocols| protocols.first())
        .cloned()
        .unwrap_or_default();
    let now = state.node.clock.as_ref().now();
    let Ok(mut session) = control.session.try_lock() else {
        return (api::StatusCode::ResourceExhausted as i32, None);
    };
    let stream_id = match session.open_stream_with_protocol(&protocol_id, open.unidirectional) {
        Ok(stream_id) => stream_id,
        Err(error) => return (session_error_status(&error), None),
    };
    let Ok(stream_handle) = state.application_data.open_stream(
        principal_id,
        connection_id.to_vec(),
        application,
        session_id,
        stream_id,
        protocol_id.clone(),
    ) else {
        return (api::StatusCode::Conflict as i32, None);
    };
    let summary = api::StreamSummary {
        stream_handle: Some(api::OpaqueHandle {
            value: stream_handle.clone(),
        }),
        session_handle: Some(api::OpaqueHandle {
            value: session_id.to_be_bytes().to_vec(),
        }),
        stream_id,
        state: "open".into(),
        bidirectional: !open.unidirectional,
        ..Default::default()
    };
    let response = api::OpenStreamResponse {
        stream_handle: summary.stream_handle.clone(),
        stream: Some(summary),
    };
    let _ = now;
    (api::StatusCode::Ok as i32, encode_payload(&response))
}

pub(crate) fn accept_stream(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(accept) = api::AcceptStreamRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let application = match owned_application(
        state,
        accept.application_handle.as_ref(),
        principal_id,
        connection_id,
    ) {
        Ok(application) => application,
        Err(code) => return (code, None),
    };
    let Some(handle) = accept
        .pending_stream_handle
        .as_ref()
        .map(|h| h.value.clone())
    else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some((owner, owner_connection, owner_application)) =
        state.application_data.stream_owner(&handle)
    else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if owner != principal_id
        || owner_connection.as_slice() != connection_id
        || owner_application != application
    {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    match state
        .application_data
        .accept_stream(&handle, principal_id, connection_id)
    {
        Ok(()) => {
            let Some((session_id, stream_id, _protocol)) =
                state.application_data.stream_metadata(&handle)
            else {
                return (api::StatusCode::NotFound as i32, None);
            };
            let summary = api::StreamSummary {
                stream_handle: Some(api::OpaqueHandle { value: handle }),
                session_handle: Some(api::OpaqueHandle {
                    value: session_id.to_be_bytes().to_vec(),
                }),
                stream_id,
                state: "open".into(),
                bidirectional: true,
                ..Default::default()
            };
            let response = api::AcceptStreamResponse {
                stream_handle: summary.stream_handle.clone(),
                stream: Some(summary),
            };
            (api::StatusCode::Ok as i32, encode_payload(&response))
        }
        Err(error) => (application_error_status(error), None),
    }
}

pub(crate) fn reject_stream(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(reject) = api::RejectStreamRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = reject
        .pending_stream_handle
        .as_ref()
        .map(|h| h.value.clone())
    else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some((owner, owner_connection, _application)) =
        state.application_data.stream_owner(&handle)
    else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if owner != principal_id || owner_connection.as_slice() != connection_id {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    let Some((session_id, stream_id, _protocol)) = state.application_data.stream_metadata(&handle)
    else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let Ok(control) = owned_session_control(state, session_id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let payload = match control.session.try_lock() {
        Ok(mut session) => session.reset_stream_payload(stream_id, reject.application_error_code),
        Err(_) => return (api::StatusCode::ResourceExhausted as i32, None),
    };
    let code = match payload {
        Ok(payload) => match send_session_payload(state, &control, &payload) {
            Ok(()) => api::StatusCode::Ok as i32,
            Err(error) => error,
        },
        Err(error) => session_error_status(&error),
    };
    if code != api::StatusCode::Ok as i32 {
        return (code, None);
    }
    match state
        .application_data
        .reject_stream(&handle, principal_id, connection_id)
    {
        Ok(()) => (
            api::StatusCode::Ok as i32,
            encode_payload(&api::RejectStreamResponse {}),
        ),
        Err(error) => (application_error_status(error), None),
    }
}

pub(crate) fn read_stream(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(read) = api::ReadStreamRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = read.stream_handle.as_ref().map(|h| h.value.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let maximum_bytes = usize::try_from(read.maximum_bytes).unwrap_or(usize::MAX);
    match state.application_data.read_stream(
        handle,
        principal_id,
        connection_id,
        maximum_bytes.min(256 * 1024),
        read.wait_for_data,
    ) {
        Ok(Some(read)) => {
            let response = api::ReadStreamResponse {
                data: read.data,
                eof: read.eof,
                reset: read.reset,
                application_error_code: read.application_error_code,
            };
            (api::StatusCode::Ok as i32, encode_payload(&response))
        }
        Ok(None) => {
            let response = api::ReadStreamResponse::default();
            (api::StatusCode::Ok as i32, encode_payload(&response))
        }
        Err(error) => (application_error_status(error), None),
    }
}

pub(crate) fn write_stream(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(write) = api::WriteStreamRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if write.data.len() > 256 * 1024 {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let Some(handle) = write.stream_handle.as_ref().map(|h| h.value.clone()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some((owner, owner_connection, _application)) =
        state.application_data.stream_owner(&handle)
    else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if owner != principal_id || owner_connection.as_slice() != connection_id {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    let Some((session_id, stream_id, _protocol)) = state.application_data.stream_metadata(&handle)
    else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let Ok(control) = owned_session_control(state, session_id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let now = state.node.clock.as_ref().now();
    let Ok(mut session) = control.session.try_lock() else {
        return (api::StatusCode::ResourceExhausted as i32, None);
    };
    let before = session
        .streams
        .get(&stream_id)
        .map_or(0, |stream| stream.next_send_offset);
    let payload = match session.send_stream_data(stream_id, &write.data, write.fin) {
        Ok(payload) => payload,
        Err(error) => return (session_error_status(&error), None),
    };
    let accepted = session
        .streams
        .get(&stream_id)
        .map_or(0, |stream| stream.next_send_offset.saturating_sub(before));
    let packet = match session.build_outbound(state.node.clock.as_ref(), now, &payload) {
        Ok(Some(packet)) => {
            session.touch(now);
            packet
        }
        Ok(None) => return (api::StatusCode::Unavailable as i32, None),
        Err(error) => return (session_error_status(&error), None),
    };
    drop(session);
    if control
        .link
        .send(OutboundPacket {
            bytes: packet,
            control: false,
            deadline_ms: None,
        })
        .is_err()
    {
        return (api::StatusCode::Unavailable as i32, None);
    }
    let fin_accepted = write.fin && accepted == u64::try_from(write.data.len()).unwrap_or(u64::MAX);
    push_event(
        state,
        "stream_bytes_accepted",
        format!(
            "stream_id {stream_id} offset {}",
            before.saturating_add(accepted)
        ),
    );
    if fin_accepted {
        let _ = state
            .application_data
            .close_stream_send(&handle, principal_id, connection_id);
    }
    let response = api::WriteStreamResponse {
        accepted_bytes: u32::try_from(accepted).unwrap_or(u32::MAX),
        fin_accepted,
    };
    (api::StatusCode::Ok as i32, encode_payload(&response))
}

fn stream_control(
    state: &mut RuntimeState,
    handle: &[u8],
    principal_id: u64,
    connection_id: &[u8],
    payload: Result<Vec<u8>, umc_session::session::SessionError>,
) -> i32 {
    let Some((owner, owner_connection, _application)) = state.application_data.stream_owner(handle)
    else {
        return api::StatusCode::NotFound as i32;
    };
    if owner != principal_id || owner_connection.as_slice() != connection_id {
        return api::StatusCode::PermissionDenied as i32;
    }
    let Some((session_id, _stream_id, _protocol)) = state.application_data.stream_metadata(handle)
    else {
        return api::StatusCode::NotFound as i32;
    };
    let Ok(control) = owned_session_control(state, session_id) else {
        return api::StatusCode::NotFound as i32;
    };
    let payload = match payload {
        Ok(payload) => payload,
        Err(error) => return session_error_status(&error),
    };
    match send_session_payload(state, &control, &payload) {
        Ok(()) => api::StatusCode::Ok as i32,
        Err(code) => code,
    }
}

fn owned_stream_metadata(
    state: &RuntimeState,
    handle: &[u8],
    principal_id: u64,
    connection_id: &[u8],
) -> Result<(u64, u64), i32> {
    let Some((owner, owner_connection, _application)) = state.application_data.stream_owner(handle)
    else {
        return Err(api::StatusCode::NotFound as i32);
    };
    if owner != principal_id || owner_connection.as_slice() != connection_id {
        return Err(api::StatusCode::PermissionDenied as i32);
    }
    state
        .application_data
        .stream_metadata(handle)
        .map(|(session_id, stream_id, _)| (session_id, stream_id))
        .ok_or(api::StatusCode::NotFound as i32)
}

pub(crate) fn close_stream_send(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(close) = api::CloseStreamSendRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = close.stream_handle.as_ref().map(|h| h.value.clone()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let (session_id, stream_id) =
        match owned_stream_metadata(state, &handle, principal_id, connection_id) {
            Ok(metadata) => metadata,
            Err(code) => return (code, None),
        };
    let Ok(control) = owned_session_control(state, session_id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let payload = match control.session.try_lock() {
        Ok(mut session) => session.close_stream_send_payload(stream_id),
        Err(_) => return (api::StatusCode::ResourceExhausted as i32, None),
    };
    let code = stream_control(state, &handle, principal_id, connection_id, payload);
    if code == api::StatusCode::Ok as i32 {
        let _ = state
            .application_data
            .close_stream_send(&handle, principal_id, connection_id);
    }
    (
        code,
        (code == api::StatusCode::Ok as i32)
            .then(|| encode_payload(&api::CloseStreamSendResponse {}))
            .flatten(),
    )
}

pub(crate) fn reset_stream(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(reset) = api::ResetStreamRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = reset.stream_handle.as_ref().map(|h| h.value.clone()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let (session_id, stream_id) =
        match owned_stream_metadata(state, &handle, principal_id, connection_id) {
            Ok(metadata) => metadata,
            Err(code) => return (code, None),
        };
    let Ok(control) = owned_session_control(state, session_id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let payload = match control.session.try_lock() {
        Ok(mut session) => session.reset_stream_payload(stream_id, reset.application_error_code),
        Err(_) => return (api::StatusCode::ResourceExhausted as i32, None),
    };
    let code = stream_control(state, &handle, principal_id, connection_id, payload);
    if code == api::StatusCode::Ok as i32 {
        push_event(
            state,
            "stream_reset",
            format!(
                "stream_id {stream_id} error {}",
                reset.application_error_code
            ),
        );
        let _ = state.application_data.mark_stream_reset(
            &handle,
            principal_id,
            connection_id,
            reset.application_error_code,
        );
    }
    (
        code,
        (code == api::StatusCode::Ok as i32)
            .then(|| encode_payload(&api::ResetStreamResponse {}))
            .flatten(),
    )
}

pub(crate) fn stop_stream(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(stop) = api::StopStreamRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = stop.stream_handle.as_ref().map(|h| h.value.clone()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let (session_id, stream_id) =
        match owned_stream_metadata(state, &handle, principal_id, connection_id) {
            Ok(metadata) => metadata,
            Err(code) => return (code, None),
        };
    let Ok(control) = owned_session_control(state, session_id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let payload = match control.session.try_lock() {
        Ok(mut session) => session.stop_stream_payload(stream_id, stop.application_error_code),
        Err(_) => return (api::StatusCode::ResourceExhausted as i32, None),
    };
    let code = stream_control(state, &handle, principal_id, connection_id, payload);
    if code == api::StatusCode::Ok as i32 {
        push_event(
            state,
            "stream_stopped",
            format!(
                "stream_id {stream_id} error {}",
                stop.application_error_code
            ),
        );
    }
    (
        code,
        (code == api::StatusCode::Ok as i32)
            .then(|| encode_payload(&api::StopStreamResponse {}))
            .flatten(),
    )
}

pub(crate) fn send_datagram(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(send) = api::SendDatagramRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if send.data.len() > umc_wire::frames::datagram::MAX_DATAGRAM_PAYLOAD {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    let Some(session_id) = session_id_from_handle(send.session_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some((owner, owner_connection, _application, pending)) =
        state.application_data.session_owner(session_id)
    else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if owner != principal_id || owner_connection.as_slice() != connection_id || pending {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    let Ok(control) = owned_session_control(state, session_id) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let now = state.node.clock.as_ref().now();
    let Ok(mut session) = control.session.try_lock() else {
        return (api::StatusCode::ResourceExhausted as i32, None);
    };
    let expires_at_ms = (send.lifetime_ms > 0).then(|| now.0.saturating_add(send.lifetime_ms));
    if let Err(error) = session.send_datagram(
        Datagram {
            context_id: send.context_id,
            data: send.data,
            expires_at_ms,
            ack_requested: send.request_ack,
        },
        umc_wire::frames::datagram::MAX_DATAGRAM_PAYLOAD,
    ) {
        return (session_error_status(&error), None);
    }
    let Some(payload) = session.pop_outbound_datagram_payload(now.0) else {
        return (api::StatusCode::Unavailable as i32, None);
    };
    let packet = match session.build_outbound(state.node.clock.as_ref(), now, &payload) {
        Ok(Some(packet)) => {
            session.touch(now);
            packet
        }
        Ok(None) => return (api::StatusCode::Unavailable as i32, None),
        Err(error) => return (session_error_status(&error), None),
    };
    drop(session);
    if control
        .link
        .send(OutboundPacket {
            bytes: packet,
            control: false,
            deadline_ms: None,
        })
        .is_err()
    {
        return (api::StatusCode::Unavailable as i32, None);
    }
    let response = api::SendDatagramResponse {
        local_datagram_id: state.application_data.allocate_datagram_id(),
    };
    (api::StatusCode::Ok as i32, encode_payload(&response))
}

pub(crate) fn receive_datagram(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
) -> (i32, Option<Vec<u8>>) {
    let Ok(receive) = api::ReceiveDatagramRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let application = match owned_application(
        state,
        receive.application_handle.as_ref(),
        principal_id,
        connection_id,
    ) {
        Ok(application) => application,
        Err(code) => return (code, None),
    };
    let Some(session_id) = session_id_from_handle(receive.session_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some((owner, owner_connection, owner_application, pending)) =
        state.application_data.session_owner(session_id)
    else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if owner != principal_id
        || owner_connection.as_slice() != connection_id
        || owner_application != application
        || pending
    {
        return (api::StatusCode::PermissionDenied as i32, None);
    }
    match state.application_data.receive_datagram(
        session_id,
        connection_id,
        usize::try_from(receive.maximum_bytes)
            .unwrap_or(usize::MAX)
            .min(256 * 1024),
        receive.wait_for_data,
    ) {
        Ok(Some(datagram)) => {
            let response = api::ReceiveDatagramResponse {
                session_handle: Some(api::OpaqueHandle {
                    value: session_id.to_be_bytes().to_vec(),
                }),
                context_id: datagram.context_id,
                data: datagram.data,
                expired: datagram.expired,
            };
            (api::StatusCode::Ok as i32, encode_payload(&response))
        }
        Ok(None) => (
            api::StatusCode::Ok as i32,
            encode_payload(&api::ReceiveDatagramResponse::default()),
        ),
        Err(error) => (application_error_status(error), None),
    }
}

fn owns_handle(
    state: &RuntimeState,
    handle: &[u8],
    principal_id: u64,
    connection_id: &[u8],
) -> bool {
    let Some(owner) = state.application_principals.get(handle) else {
        return false;
    };
    if *owner != principal_id {
        return false;
    }
    let Some(owner_connection) = state.application_connections.get(handle) else {
        return connection_id.is_empty();
    };
    connection_id.is_empty() || owner_connection.as_slice() == connection_id
}

/// Dispatch the implemented `ApplicationService` methods for a live connection
/// while retaining the connection ID needed for handle ownership checks.
pub(crate) fn dispatch_request(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
    connection_id: &[u8],
    deadline: umc_types::runtime::Instant,
    cancellation: Option<CancellationHandle>,
) -> (i32, Option<Vec<u8>>) {
    match request.method.as_str() {
        "RegisterApplication" => register(state, request, principal_id, connection_id),
        "UnregisterApplication" => unregister(state, request, principal_id, connection_id),
        "OpenListener" => open_listener(state, request, principal_id, connection_id),
        "CloseListener" => close_listener(state, request, principal_id, connection_id),
        "Connect" => connect(
            state,
            request,
            principal_id,
            connection_id,
            deadline,
            cancellation,
        ),
        "AcceptIncomingSession" => {
            accept_incoming_session(state, request, principal_id, connection_id)
        }
        "RejectIncomingSession" => {
            reject_incoming_session(state, request, principal_id, connection_id)
        }
        "OpenStream" => open_stream(state, request, principal_id, connection_id),
        "AcceptStream" => accept_stream(state, request, principal_id, connection_id),
        "RejectStream" => reject_stream(state, request, principal_id, connection_id),
        "ReadStream" => read_stream(state, request, principal_id, connection_id),
        "WriteStream" => write_stream(state, request, principal_id, connection_id),
        "CloseStreamSend" => close_stream_send(state, request, principal_id, connection_id),
        "ResetStream" => reset_stream(state, request, principal_id, connection_id),
        "StopStream" => stop_stream(state, request, principal_id, connection_id),
        "SendDatagram" => send_datagram(state, request, principal_id, connection_id),
        "ReceiveDatagram" => receive_datagram(state, request, principal_id, connection_id),
        _ => (api::StatusCode::Unimplemented as i32, None),
    }
}

/// Remove all application registrations owned by a closed live connection.
pub(crate) fn close_connection(state: &mut RuntimeState, connection_id: &[u8]) {
    if connection_id.is_empty() {
        return;
    }
    let handles: Vec<Vec<u8>> = state
        .application_connections
        .iter()
        .filter(|(_, owner)| owner.as_slice() == connection_id)
        .map(|(handle, _)| handle.clone())
        .collect();
    if handles.is_empty() {
        state.application_data.remove_connection(connection_id);
        return;
    }
    let mut channels = state.app_channels.lock().expect("app channels");
    let mut receivers = state.app_echo_rx.lock().expect("app echo receivers");
    for handle in handles {
        if state
            .application_registrations
            .get(&handle)
            .is_some_and(|registration| registration.resumable)
        {
            state
                .application_connections
                .insert(handle.clone(), Vec::new());
            if let Some(principal_id) = state.application_principals.get(&handle).copied() {
                let _ = state
                    .application_data
                    .rebind_application(&handle, principal_id, &[]);
            }
            push_event(
                state,
                "application_suspended",
                "control connection closed".to_string(),
            );
            continue;
        }
        for session_id in state.application_data.session_ids_for_application(&handle) {
            if let Some(entry) = state.sessions.lookup(session_id) {
                entry.task.abort();
            }
        }
        if let Some(protocol_ids) = state.application_protocols.remove(&handle) {
            for protocol_id in protocol_ids {
                let _ = state.apps.unregister(&protocol_id);
                channels.remove(&protocol_id);
                receivers.remove(&protocol_id);
            }
        }
        state.application_principals.remove(&handle);
        state.application_connections.remove(&handle);
        state.application_registrations.remove(&handle);
        state.application_listeners.remove(&handle);
        state.application_data.remove_application(&handle);
        push_event(
            state,
            "application_unregistered",
            "control connection closed".to_string(),
        );
    }
    state.application_data.remove_connection(connection_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use tokio::sync::mpsc;
    use umc_carrier::error::{CarrierError, CarrierErrorKind};
    use umc_carrier::types::{
        InboundPacket, LinkEvent, LinkProperties, Ordering, QueueState, Reliability, SendResult,
    };
    use umc_carrier::{BoxLink, Link};
    use umc_session::session::{Role, Session, SessionConfig};

    #[derive(Clone)]
    struct TestLink {
        sent: StdArc<StdMutex<Vec<OutboundPacket>>>,
    }

    impl Link for TestLink {
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
            self.sent.lock().expect("sent packets").push(packet);
            Ok(SendResult::Accepted {
                queue_state: QueueState::SentToMedium,
            })
        }

        fn recv(&self) -> Result<InboundPacket, CarrierError> {
            Err(CarrierError::new(CarrierErrorKind::WouldBlock, "test"))
        }

        fn events(&self) -> Result<LinkEvent, CarrierError> {
            Err(CarrierError::new(CarrierErrorKind::WouldBlock, "test"))
        }

        fn close(&self, _reason: &str) -> Result<(), CarrierError> {
            Ok(())
        }
    }

    fn request(method: &str, payload: Vec<u8>) -> api::Request {
        api::Request {
            request_id: 1,
            service: "ApplicationService".into(),
            method: method.into(),
            payload,
            ..Default::default()
        }
    }

    fn encode<M: Message>(message: &M) -> Vec<u8> {
        let mut payload = Vec::new();
        message.encode(&mut payload).expect("encode");
        payload
    }

    fn state() -> RuntimeState {
        static STATE_COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "umcd-application-control-{}-{}",
            std::process::id(),
            STATE_COUNTER.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let (shutdown, _receiver) = mpsc::channel(1);
        RuntimeState::new(
            crate::config::NodeConfig {
                data_dir: dir,
                ..Default::default()
            },
            shutdown,
        )
        .expect("runtime state")
    }

    #[test]
    fn register_returns_effective_application_grants_without_expanding_authority() {
        let mut state = state();
        let principal_id = 42;
        state.token_grants.insert(
            principal_id,
            vec![
                api::CapabilityGrant {
                    capability: api::Capability::ApplicationRegister as i32,
                    ..Default::default()
                },
                api::CapabilityGrant {
                    capability: api::Capability::ApplicationListen as i32,
                    constraints: Some(api::ResourceConstraints {
                        protocol_ids: vec!["org.notes/1".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                api::CapabilityGrant {
                    capability: api::Capability::NodeAdmin as i32,
                    ..Default::default()
                },
            ],
        );
        let response = register(
            &mut state,
            &request(
                "RegisterApplication",
                encode(&api::RegisterApplicationRequest {
                    application_name: "notes".into(),
                    application_instance_id: vec![7; 16],
                    requested_protocol_ids: vec!["org.notes/1".into()],
                    requested_capabilities: vec![
                        api::Capability::ApplicationListen as i32,
                        api::Capability::ApplicationConnect as i32,
                    ],
                    ..Default::default()
                }),
            ),
            principal_id,
            b"connection-1",
        );
        assert_eq!(response.0, api::StatusCode::Ok as i32);
        let response = api::RegisterApplicationResponse::decode(
            response.1.expect("registration response").as_slice(),
        )
        .expect("decode registration response");
        assert_eq!(response.effective_grants.len(), 1);
        assert_eq!(
            response.effective_grants[0].capability,
            api::Capability::ApplicationListen as i32
        );
        assert!(response.resume_token.is_empty());
    }

    #[test]
    fn resumable_registration_reclaims_application_after_connection_loss() {
        let mut state = state();
        let request = request(
            "RegisterApplication",
            encode(&api::RegisterApplicationRequest {
                application_name: "notes".into(),
                application_instance_id: vec![9; 16],
                requested_protocol_ids: vec!["org.notes/1".into()],
                resumable: true,
                ..Default::default()
            }),
        );
        let first = register(&mut state, &request, 42, b"connection-1");
        assert_eq!(first.0, api::StatusCode::Ok as i32);
        let first = api::RegisterApplicationResponse::decode(
            first.1.expect("first registration response").as_slice(),
        )
        .expect("decode first registration response");
        assert!(!first.resume_token.is_empty());
        let handle = first
            .application_handle
            .expect("first application handle")
            .value;
        state.application_data.register_listener(
            b"org.notes/1".to_vec(),
            handle.clone(),
            42,
            b"connection-1".to_vec(),
        );

        close_connection(&mut state, b"connection-1");
        assert!(state.apps.lookup(&handle).is_some());

        let second = register(&mut state, &request, 42, b"connection-2");
        assert_eq!(second.0, api::StatusCode::Ok as i32);
        let second = api::RegisterApplicationResponse::decode(
            second.1.expect("second registration response").as_slice(),
        )
        .expect("decode second registration response");
        assert_eq!(second.application_handle.expect("second handle").value, handle);
        assert_eq!(second.resume_token, first.resume_token);
        assert_eq!(
            state.application_connections.get(&handle).map(Vec::as_slice),
            Some(b"connection-2".as_slice())
        );
        state
            .application_data
            .route_incoming_stream(9, 1, b"org.notes/1", b"pending".to_vec(), false)
            .expect("rebound listener");
        let pending = state
            .application_data
            .pending_streams()
            .into_iter()
            .next()
            .expect("pending stream handle");
        assert!(matches!(
            state
                .application_data
                .read_stream(&pending, 42, b"connection-2", 32, false),
            Err(crate::application_data::ApplicationDataError::Pending)
        ));
    }

    #[test]
    fn p2_relay_selection_requires_usable_cached_next_hop() {
        let mut state = state();
        let destination = [3u8; 32];
        let relay_peer = [7u8; 32];
        let (in_tx, _in_rx) = mpsc::unbounded_channel();
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        state
            .bus
            .lock()
            .expect("session bus")
            .register(relay_peer.to_vec(), 1, in_tx, out_tx);
        let metadata = umc_routing::paths::encode_path_metadata(&[
            umc_routing::paths::PathHop {
                peer: relay_peer.to_vec(),
                scope: RouteScope::General,
                failure_domain: Vec::new(),
                relay: true,
            },
            umc_routing::paths::PathHop {
                peer: destination.to_vec(),
                scope: RouteScope::General,
                failure_domain: Vec::new(),
                relay: false,
            },
        ])
        .expect("path metadata");
        let _ = state.routing.record_route_response_with_metadata(
            RouteKey {
                destination_profile: 0,
                destination_hash: crate::session_task::hash_destination(&destination),
                scope: RouteScope::General,
                policy_class: 0,
            },
            "07".repeat(32),
            60_000,
            state.node.clock.as_ref().now(),
            None,
            metadata,
        );
        let route = api::RoutePolicy {
            scope: api::RouteScope::General as i32,
            allow_relay: true,
            ..Default::default()
        };
        assert_eq!(
            relay_peer_for_destination(&state, &destination, &route),
            Some(relay_peer.to_vec())
        );
        let missing = api::RoutePolicy {
            scope: api::RouteScope::LocalMesh as i32,
            ..route
        };
        assert!(relay_peer_for_destination(&state, &destination, &missing).is_none());
    }

    #[test]
    fn p2_relay_selection_accepts_explicit_relay_carrier_allow_list() {
        let mut state = state();
        let destination = [3u8; 32];
        let relay_peer = [7u8; 32];
        let (in_tx, _in_rx) = mpsc::unbounded_channel();
        let (out_tx, _out_rx) = mpsc::unbounded_channel();
        state
            .bus
            .lock()
            .expect("session bus")
            .register(relay_peer.to_vec(), 1, in_tx, out_tx);
        let metadata = umc_routing::paths::encode_path_metadata(&[
            umc_routing::paths::PathHop {
                peer: relay_peer.to_vec(),
                scope: RouteScope::General,
                failure_domain: Vec::new(),
                relay: true,
            },
            umc_routing::paths::PathHop {
                peer: destination.to_vec(),
                scope: RouteScope::General,
                failure_domain: Vec::new(),
                relay: false,
            },
        ])
        .expect("path metadata");
        let _ = state.routing.record_route_response_with_metadata(
            RouteKey {
                destination_profile: 0,
                destination_hash: destination,
                scope: RouteScope::General,
                policy_class: 0,
            },
            "07".repeat(32),
            60_000,
            state.node.clock.as_ref().now(),
            None,
            metadata,
        );
        let route = api::RoutePolicy {
            scope: api::RouteScope::General as i32,
            allow_relay: true,
            allowed_carrier_types: vec!["ump.relay/1".into()],
            ..Default::default()
        };
        assert_eq!(
            relay_peer_for_destination(&state, &destination, &route),
            Some(relay_peer.to_vec())
        );
    }

    #[test]
    fn p2_relay_selection_keeps_diverse_alternatives_after_failure() {
        let mut state = state();
        let destination = [3u8; 32];
        let first = [7u8; 32];
        let second = [8u8; 32];
        for (session_id, peer) in [(1, first), (2, second)] {
            let (in_tx, _in_rx) = mpsc::unbounded_channel();
            let (out_tx, _out_rx) = mpsc::unbounded_channel();
            state.bus.lock().expect("session bus").register(
                peer.to_vec(),
                session_id,
                in_tx,
                out_tx,
            );
        }
        let metadata = |peer: [u8; 32]| {
            umc_routing::paths::encode_path_metadata(&[
                umc_routing::paths::PathHop {
                    peer: peer.to_vec(),
                    scope: RouteScope::General,
                    failure_domain: Vec::new(),
                    relay: true,
                },
                umc_routing::paths::PathHop {
                    peer: destination.to_vec(),
                    scope: RouteScope::General,
                    failure_domain: Vec::new(),
                    relay: false,
                },
            ])
            .expect("path metadata")
        };
        let key = RouteKey {
            destination_profile: 0,
            destination_hash: crate::session_task::hash_destination(&destination),
            scope: RouteScope::General,
            policy_class: 0,
        };
        let now = state.node.clock.as_ref().now();
        for peer in [first, second] {
            let _ = state.routing.record_route_response_with_metadata(
                key.clone(),
                endpoint_label(&peer),
                60_000,
                now,
                None,
                metadata(peer),
            );
        }
        let route = api::RoutePolicy {
            scope: api::RouteScope::General as i32,
            allow_relay: true,
            ..Default::default()
        };
        let peers = relay_peers_for_destination(&state, &destination, &route);
        assert_eq!(peers, vec![first.to_vec(), second.to_vec()]);
        let first_label = endpoint_label(&first);
        assert!(state.routing.mark_route_failure(&key, &first_label, now));
        let peers = relay_peers_for_destination(&state, &destination, &route);
        assert_eq!(peers, vec![second.to_vec()]);
    }

    #[test]
    fn connect_route_policy_rejects_invalid_and_unavailable_trust_floors() {
        let invalid_scope = api::ConnectRequest {
            policy: Some(api::ConnectionPolicy {
                route: Some(api::RoutePolicy {
                    scope: 99,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            validate_connect_route_policy(&invalid_scope),
            Err(api::StatusCode::InvalidArgument as i32)
        );

        let invalid_trust = api::ConnectRequest {
            policy: Some(api::ConnectionPolicy {
                route: Some(api::RoutePolicy {
                    minimum_trust: 99,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            validate_connect_route_policy(&invalid_trust),
            Err(api::StatusCode::InvalidArgument as i32)
        );

        let unavailable_trust = api::ConnectRequest {
            policy: Some(api::ConnectionPolicy {
                route: Some(api::RoutePolicy {
                    minimum_trust: api::TrustState::Trusted as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            validate_connect_route_policy(&unavailable_trust),
            Err(api::StatusCode::FailedPrecondition as i32)
        );
    }

    fn install_session(
        state: &mut RuntimeState,
        session_id: u64,
        sent: StdArc<StdMutex<Vec<OutboundPacket>>>,
    ) {
        let session = Session::new(
            SessionConfig {
                role: Role::Client,
                dcid: vec![0; 8],
                local_traffic_secret: [1; 32],
                remote_traffic_secret: [2; 32],
                initial_max_data: umc_session::session::DEFAULT_INITIAL_MAX_DATA,
                initial_max_stream_data: umc_session::session::DEFAULT_INITIAL_MAX_STREAM_DATA,
                max_ack_delay_ms: 25,
            },
            state.node.clock.as_ref(),
        )
        .expect("session");
        let link: BoxLink = Box::new(TestLink { sent });
        let session = StdArc::new(tokio::sync::Mutex::new(session));
        state.session_controls.insert(
            session_id,
            StdArc::new(crate::session_manager::SessionControl::new(
                session,
                StdArc::new(link),
            )),
        );
        state.sessions.register(
            session_id,
            crate::session_manager::SessionEntry {
                peer_endpoint_id: [9; 32],
                carrier_type: "ump.test/1".into(),
                task: tokio::spawn(async {}).abort_handle(),
                established_at_ms: 1,
                privacy_profile: 0,
                direct_path_allowed: true,
                traffic_padding_active: false,
            },
        );
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test(flavor = "multi_thread")]
    async fn established_application_stream_and_datagram_round_trip() {
        let mut state = state();
        let principal_id = 7;
        let connection_id = b"control-1";
        let registered = register(
            &mut state,
            &request(
                "RegisterApplication",
                encode(&api::RegisterApplicationRequest {
                    application_name: "test".into(),
                    requested_protocol_ids: vec!["org.test/1".into()],
                    ..Default::default()
                }),
            ),
            principal_id,
            connection_id,
        );
        assert_eq!(registered.0, api::StatusCode::Ok as i32);
        let application = api::RegisterApplicationResponse::decode(
            registered.1.as_deref().expect("registration payload"),
        )
        .expect("registration response")
        .application_handle
        .expect("application handle");

        let session_id = state.sessions.next_id();
        let sent = StdArc::new(StdMutex::new(Vec::new()));
        install_session(&mut state, session_id, sent.clone());
        let opened = open_stream(
            &mut state,
            &request(
                "OpenStream",
                encode(&api::OpenStreamRequest {
                    application_handle: Some(application.clone()),
                    session_handle: Some(api::OpaqueHandle {
                        value: session_id.to_be_bytes().to_vec(),
                    }),
                    ..Default::default()
                }),
            ),
            principal_id,
            connection_id,
        );
        assert_eq!(opened.0, api::StatusCode::Ok as i32);
        let stream = api::OpenStreamResponse::decode(opened.1.as_deref().expect("open payload"))
            .expect("open response")
            .stream_handle
            .expect("stream handle");

        let written = write_stream(
            &mut state,
            &request(
                "WriteStream",
                encode(&api::WriteStreamRequest {
                    stream_handle: Some(stream.clone()),
                    data: b"hello".to_vec(),
                    fin: true,
                }),
            ),
            principal_id,
            connection_id,
        );
        assert_eq!(written.0, api::StatusCode::Ok as i32);
        let written =
            api::WriteStreamResponse::decode(written.1.as_deref().expect("write payload"))
                .expect("write response");
        assert_eq!(written.accepted_bytes, 5);
        assert!(written.fin_accepted);
        assert!(!sent.lock().expect("sent packets").is_empty());

        state
            .application_data
            .push_stream_data(&stream.value, b"reply".to_vec(), true)
            .expect("inbound data");
        let read = read_stream(
            &mut state,
            &request(
                "ReadStream",
                encode(&api::ReadStreamRequest {
                    stream_handle: Some(stream.clone()),
                    maximum_bytes: 64,
                    ..Default::default()
                }),
            ),
            principal_id,
            connection_id,
        );
        assert_eq!(read.0, api::StatusCode::Ok as i32);
        let read = api::ReadStreamResponse::decode(read.1.as_deref().expect("read payload"))
            .expect("read response");
        assert_eq!(read.data, b"reply");
        assert!(read.eof);

        let sent_datagram = send_datagram(
            &mut state,
            &request(
                "SendDatagram",
                encode(&api::SendDatagramRequest {
                    session_handle: Some(api::OpaqueHandle {
                        value: session_id.to_be_bytes().to_vec(),
                    }),
                    context_id: 41,
                    data: b"dgram".to_vec(),
                    lifetime_ms: 1000,
                    request_ack: true,
                }),
            ),
            principal_id,
            connection_id,
        );
        assert_eq!(sent_datagram.0, api::StatusCode::Ok as i32);
        state
            .application_data
            .push_datagram(session_id, 42, b"inbound".to_vec(), false)
            .expect("inbound datagram");
        let received = receive_datagram(
            &mut state,
            &request(
                "ReceiveDatagram",
                encode(&api::ReceiveDatagramRequest {
                    application_handle: Some(application),
                    session_handle: Some(api::OpaqueHandle {
                        value: session_id.to_be_bytes().to_vec(),
                    }),
                    maximum_bytes: 64,
                    ..Default::default()
                }),
            ),
            principal_id,
            connection_id,
        );
        assert_eq!(received.0, api::StatusCode::Ok as i32);
        let received =
            api::ReceiveDatagramResponse::decode(received.1.as_deref().expect("receive payload"))
                .expect("receive response");
        assert_eq!(received.context_id, 42);
        assert_eq!(received.data, b"inbound");
    }

    #[tokio::test]
    async fn connect_wait_returns_cancelled_before_deadline() {
        let cancellation = CancellationHandle::new();
        let waiter = cancellation.clone();
        let task = tokio::spawn(race_deadline_or_cancellation(
            std::future::pending::<Result<(), String>>(),
            60_000,
            Some(waiter),
        ));
        cancellation.cancel();
        assert_eq!(task.await.expect("connect wait"), Err("cancelled".into()));
    }

    #[test]
    fn connect_target_resolves_an_authenticated_static_peer_hint() {
        let config = crate::config::NodeConfig {
            static_peers: vec![crate::config::StaticPeerConfig {
                endpoint_id: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                    .into(),
                carrier: "ump.tcp/1".into(),
                address: "127.0.0.1:9001".into(),
            }],
            ..Default::default()
        };
        let target = resolve_static_peer(
            &config,
            &[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                0xcc, 0xdd, 0xee, 0xff,
            ],
        )
        .expect("destination endpoint id resolves");
        assert_eq!(target.carrier, "ump.tcp/1");
        assert_eq!(target.address, "127.0.0.1:9001");
        assert_eq!(
            target.endpoint_id,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                0xcc, 0xdd, 0xee, 0xff
            ]
        );
    }

    #[test]
    fn connect_rejects_static_carrier_outside_requested_allow_list() {
        let mut state = state();
        state.config.static_peers = vec![crate::config::StaticPeerConfig {
            endpoint_id: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
            carrier: "ump.tcp/1".into(),
            address: "127.0.0.1:9001".into(),
        }];
        let principal_id = 19;
        let connection_id = b"control-carrier-policy";
        let registered = register(
            &mut state,
            &request(
                "RegisterApplication",
                encode(&api::RegisterApplicationRequest {
                    application_name: "carrier-policy-test".into(),
                    requested_protocol_ids: vec!["org.test/1".into()],
                    ..Default::default()
                }),
            ),
            principal_id,
            connection_id,
        );
        assert_eq!(registered.0, api::StatusCode::Ok as i32);
        let application = api::RegisterApplicationResponse::decode(
            registered.1.as_deref().expect("registration payload"),
        )
        .expect("registration response")
        .application_handle
        .expect("application handle");

        let deadline =
            state.node.clock.as_ref().now() + umc_types::runtime::Duration::from_millis(5_000);
        let result = connect(
            &mut state,
            &request(
                "Connect",
                encode(&api::ConnectRequest {
                    application_handle: Some(application),
                    destination_hint: b"127.0.0.1:9001".to_vec(),
                    protocol_id: "org.test/1".into(),
                    policy: Some(api::ConnectionPolicy {
                        route: Some(api::RoutePolicy {
                            allowed_carrier_types: vec!["ump.udp/1".into()],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            ),
            principal_id,
            connection_id,
            deadline,
            None,
        );
        assert_eq!(result, (api::StatusCode::FailedPrecondition as i32, None));
        assert!(state.sessions.snapshot().is_empty());
        assert!(state
            .events
            .lock()
            .expect("event log")
            .recent(16)
            .iter()
            .any(|event| event.kind == "carrier_policy_rejected"));
    }

    #[test]
    fn connect_rejects_invalid_route_scope_before_dial() {
        let mut state = state();
        state.config.static_peers = vec![crate::config::StaticPeerConfig {
            endpoint_id: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
            carrier: "ump.tcp/1".into(),
            address: "127.0.0.1:9001".into(),
        }];
        let principal_id = 23;
        let connection_id = b"control-invalid-route";
        let registered = register(
            &mut state,
            &request(
                "RegisterApplication",
                encode(&api::RegisterApplicationRequest {
                    application_name: "invalid-route-test".into(),
                    requested_protocol_ids: vec!["org.test/1".into()],
                    ..Default::default()
                }),
            ),
            principal_id,
            connection_id,
        );
        assert_eq!(registered.0, api::StatusCode::Ok as i32);
        let application = api::RegisterApplicationResponse::decode(
            registered.1.as_deref().expect("registration payload"),
        )
        .expect("registration response")
        .application_handle
        .expect("application handle");

        let deadline =
            state.node.clock.as_ref().now() + umc_types::runtime::Duration::from_millis(5_000);
        let result = connect(
            &mut state,
            &request(
                "Connect",
                encode(&api::ConnectRequest {
                    application_handle: Some(application),
                    destination_hint: b"127.0.0.1:9001".to_vec(),
                    protocol_id: "org.test/1".into(),
                    policy: Some(api::ConnectionPolicy {
                        route: Some(api::RoutePolicy {
                            scope: 99,
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            ),
            principal_id,
            connection_id,
            deadline,
            None,
        );
        assert_eq!(result, (api::StatusCode::InvalidArgument as i32, None));
        assert!(state.sessions.snapshot().is_empty());
    }

    #[test]
    fn connect_fails_closed_before_direct_dial_for_p2() {
        let mut state = state();
        state.config.privacy_profile = "p2".into();
        state.config.static_peers = vec![crate::config::StaticPeerConfig {
            endpoint_id: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
            carrier: "ump.tcp/1".into(),
            address: "127.0.0.1:9001".into(),
        }];
        let principal_id = 17;
        let connection_id = b"control-p2";
        let registered = register(
            &mut state,
            &request(
                "RegisterApplication",
                encode(&api::RegisterApplicationRequest {
                    application_name: "p2-test".into(),
                    requested_protocol_ids: vec!["org.test/1".into()],
                    ..Default::default()
                }),
            ),
            principal_id,
            connection_id,
        );
        assert_eq!(registered.0, api::StatusCode::Ok as i32);
        let application = api::RegisterApplicationResponse::decode(
            registered.1.as_deref().expect("registration payload"),
        )
        .expect("registration response")
        .application_handle
        .expect("application handle");

        let deadline =
            state.node.clock.as_ref().now() + umc_types::runtime::Duration::from_millis(5_000);
        let result = connect(
            &mut state,
            &request(
                "Connect",
                encode(&api::ConnectRequest {
                    application_handle: Some(application),
                    destination_hint: b"127.0.0.1:9001".to_vec(),
                    protocol_id: "org.test/1".into(),
                    ..Default::default()
                }),
            ),
            principal_id,
            connection_id,
            deadline,
            None,
        );
        assert_eq!(result, (api::StatusCode::FailedPrecondition as i32, None));
        assert!(state.sessions.snapshot().is_empty());
    }
}
