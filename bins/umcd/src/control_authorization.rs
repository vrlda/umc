//! Live control-socket authorization (control-api.md §§11-15).
//!
//! Keeping the capability table outside the transport/service dispatcher is
//! intentional: the daemon can evolve individual services without silently
//! changing the authorization boundary, and the table can later be replaced
//! by a persisted policy evaluator.

use crate::state::{wall_now, RuntimeState};
use prost::Message;
use std::collections::HashMap;
use umc_control::auth::{TokenRecordSnapshot, TokenRegistry};
use umc_control::grants::GrantSet;
use umc_control::proto::umc::api::v1 as api;
use umc_storage::store::{Namespace, Store, StoreError};

const CONTROL_TOKEN_PREFIX: &[u8] = b"control-token/";
const CONTROL_TOKEN_NEXT_ID_KEY: &[u8] = b"control-token/__next-id";

#[derive(Clone, PartialEq, Message)]
struct PersistedControlToken {
    #[prost(uint64, tag = "1")]
    principal_id: u64,
    #[prost(bytes, tag = "2")]
    token_hash: Vec<u8>,
    #[prost(uint64, optional, tag = "3")]
    expires_at_ms: Option<u64>,
    #[prost(message, repeated, tag = "4")]
    grants: Vec<api::CapabilityGrant>,
}

/// Restore bearer metadata and grants from the protected local store. Raw
/// bearer tokens are never persisted; malformed records are ignored so a
/// corrupt row cannot turn into an accepted credential.
pub(crate) fn restore_control_tokens(
    store: &dyn Store,
) -> (TokenRegistry, HashMap<u64, Vec<api::CapabilityGrant>>) {
    let mut records = Vec::new();
    let mut grants = HashMap::new();
    let mut next_id = 1;
    let entries = match store.scan(Namespace::Api) {
        Ok(entries) => entries,
        Err(error) => {
            log::error!("[auth] failed to restore control tokens: {error:?}");
            return (TokenRegistry::new(), grants);
        }
    };
    for entry in entries {
        if entry.key == CONTROL_TOKEN_NEXT_ID_KEY {
            if let Ok(bytes) = <[u8; 8]>::try_from(entry.value.as_slice()) {
                let candidate = u64::from_be_bytes(bytes);
                if candidate > 0 && candidate < u64::MAX {
                    next_id = candidate;
                } else {
                    log::error!("[auth] ignoring invalid control-token id high-water mark");
                }
            } else {
                log::error!("[auth] ignoring corrupt control-token id high-water mark");
            }
            continue;
        }
        if !entry.key.starts_with(CONTROL_TOKEN_PREFIX) {
            continue;
        }
        let Ok(record) = PersistedControlToken::decode(entry.value.as_slice()) else {
            log::error!("[auth] ignoring corrupt persisted control token record");
            continue;
        };
        if record.principal_id == 0
            || record.principal_id == u64::MAX
            || record.token_hash.len() != 32
        {
            log::error!("[auth] ignoring invalid persisted control token metadata");
            continue;
        }
        records.push(TokenRecordSnapshot {
            principal_id: record.principal_id,
            token_hash: record.token_hash,
            expires_at_ms: record.expires_at_ms,
        });
        grants.insert(record.principal_id, record.grants);
    }
    (
        TokenRegistry::from_records_with_next_id(records, next_id),
        grants,
    )
}

/// Persist one token's hash, expiry, principal, and effective grants.
pub(crate) fn persist_control_token(
    state: &RuntimeState,
    principal_id: u64,
) -> Result<(), StoreError> {
    let Some(snapshot) = state.token_registry.snapshot(principal_id) else {
        return Err(StoreError::NotFound);
    };
    let record = PersistedControlToken {
        principal_id,
        token_hash: snapshot.token_hash,
        expires_at_ms: snapshot.expires_at_ms,
        grants: state
            .token_grants
            .get(&principal_id)
            .cloned()
            .unwrap_or_default(),
    };
    let entries = vec![
        (control_token_key(principal_id), record.encode_to_vec()),
        (
            CONTROL_TOKEN_NEXT_ID_KEY.to_vec(),
            state.token_registry.next_id().to_be_bytes().to_vec(),
        ),
    ];
    state.store.put_batch(Namespace::Api, &entries)
}

/// Remove one persisted bearer record after revocation.
pub(crate) fn delete_persisted_control_token(
    state: &RuntimeState,
    principal_id: u64,
) -> Result<(), StoreError> {
    state
        .store
        .delete(Namespace::Api, &control_token_key(principal_id))
}

fn control_token_key(principal_id: u64) -> Vec<u8> {
    format!("control-token/{principal_id:016x}").into_bytes()
}

/// Return the capability required by a control method. This is deliberately a
/// single table at the live transport boundary: service implementations stay
/// usable in unit tests, while every request received over a control socket is
/// subject to the same capability check (control-api.md §§12-15).
fn required_capability(service: &str, method: &str) -> Option<api::Capability> {
    use api::Capability as C;
    match (service, method) {
        ("NodeAdmin", "GetStatus" | "GetConfig" | "GetEvents") | ("ConfigService", "GetConfig") => {
            Some(C::NodeRead)
        }
        ("NodeAdmin", "UpdateConfig" | "ReloadConfig") | ("ConfigService", "SetConfig") => {
            Some(C::NodeAdmin)
        }
        ("NodeAdmin", "Shutdown") => Some(C::NodeShutdown),

        ("PeerService", "ListPeers" | "GetPeer") => Some(C::PeerRead),
        (
            "PeerService",
            "AddPeerHint" | "RemovePeer" | "CreateInvitation" | "ImportInvitation"
            | "RevokeInvitation",
        ) => Some(C::PeerAdmin),
        ("PeerService", "SetTrustState" | "BlockPeer" | "UnblockPeer") => Some(C::TrustAdmin),
        ("PeerService" | "DiscoveryService", "ListCandidates") => Some(C::DiscoveryRead),

        ("SessionService", "ListSessions" | "GetSession" | "ListStreams") => Some(C::SessionRead),
        ("SessionService", "CloseSession") => Some(C::SessionClose),
        ("SessionService", "MigrateSession") => Some(C::SessionMigrate),

        ("RouteService", "ListRoutes" | "GetRoute") => Some(C::RouteRead),
        ("RouteService", "ProbeRoute" | "InvalidateRoute") => Some(C::RouteProbe),

        ("BundleService", "GetBundles" | "ListBundles" | "GetBundle") => Some(C::BundleRead),
        ("BundleService", "CreateBundle") => Some(C::BundleCreate),
        ("BundleService", "DeleteBundle") => Some(C::BundleDelete),

        ("RelayService", "GetRelayStatus" | "ListRelayCircuits") => Some(C::RelayRead),
        (
            "RelayService",
            "OpenCircuit" | "CloseCircuit" | "UpdateRelayPolicy" | "CloseRelayCircuit",
        ) => Some(C::RelayAdmin),

        ("IdentityService", "ListIdentities" | "GetIdentity") => Some(C::IdentityRead),
        ("IdentityService", "CreateIdentity" | "ImportIdentity") => Some(C::IdentityCreate),
        ("IdentityService", "RotateHandshakeKey" | "RotateIdentityKey") => Some(C::IdentityRotate),
        ("IdentityService", "ExportPublicIdentity") => Some(C::IdentityExportPublic),
        ("IdentityService", "ExportSecretIdentity") => Some(C::IdentityExportSecret),
        ("IdentityService", "DeleteIdentity") => Some(C::IdentityDelete),

        (
            "CarrierService",
            "ListCarrierTypes"
            | "ListCarrierInstances"
            | "GetCarrierInstance"
            | "ListLinks"
            | "GetLinkProperties"
            | "GetLinkStats",
        ) => Some(C::CarrierRead),
        (
            "CarrierService",
            "CreateCarrierInstance"
            | "UpdateCarrierInstance"
            | "StartCarrier"
            | "StopCarrier"
            | "DeleteCarrierInstance"
            | "Listen"
            | "Dial"
            | "CloseLink",
        ) => Some(C::CarrierAdmin),

        (
            "ApplicationService",
            "RegisterApplication" | "UnregisterApplication" | "CloseListener",
        ) => Some(C::ApplicationRegister),
        ("ApplicationService", "Connect") => Some(C::ApplicationConnect),
        ("ApplicationService", "OpenListener") => Some(C::ApplicationListen),
        (
            "ApplicationService",
            "AcceptIncomingSession"
            | "RejectIncomingSession"
            | "OpenStream"
            | "AcceptStream"
            | "RejectStream"
            | "ReadStream"
            | "WriteStream"
            | "CloseStreamSend"
            | "ResetStream"
            | "StopStream",
        ) => Some(C::ApplicationStream),
        ("ApplicationService", "SendDatagram" | "ReceiveDatagram") => Some(C::ApplicationDatagram),

        (
            "DiagnosticsService",
            "RunDoctor" | "Doctor" | "GetMetricsSnapshot" | "GetSubsystemHealth",
        ) => Some(C::DiagnosticsRead),
        ("EventService", "Subscribe" | "Unsubscribe") => Some(C::EventSubscribe),
        ("TokenService", "ListGrants" | "CreateToken" | "RevokeToken" | "InspectCurrentGrant") => {
            Some(C::TokenAdmin)
        }
        _ => None,
    }
}

/// Authorize a request that arrived through a live control connection. The
/// The service dispatcher remains directly usable by in-process tests; this
/// helper is the authorization boundary exposed by the Unix control socket.
/// `os_peer_authenticated` is the proof captured by the Unix listener before
/// it reads a hello. A missing bearer token is therefore accepted only for the
/// validated same-uid local operator; it is never an ambient anonymous mode.
pub(crate) fn authorize_live_request_with_peer(
    state: &RuntimeState,
    request: &api::Request,
    presented_token: Option<&[u8]>,
    os_peer_authenticated: bool,
) -> Result<(), i32> {
    // The Unix listener is the first authentication gate. Requiring its
    // proof here as well keeps future transports or in-process callers from
    // accidentally turning a bearer credential into a socket bypass.
    if !os_peer_authenticated {
        return Err(api::StatusCode::Unauthenticated as i32);
    }
    if let Some(configured) = &state.development_token {
        return if presented_token.is_some_and(|token| token == configured.as_slice()) {
            Ok(())
        } else {
            Err(api::StatusCode::Unauthenticated as i32)
        };
    }

    let Some(token) = presented_token else {
        if request.service == "TokenService" {
            return Err(api::StatusCode::PermissionDenied as i32);
        }
        return Ok(());
    };
    let Some(principal_id) = control_principal_id(state, Some(token)) else {
        return Err(api::StatusCode::Unauthenticated as i32);
    };
    let Some(capability) = required_capability(&request.service, &request.method) else {
        return Ok(());
    };
    let grants = state
        .token_grants
        .get(&principal_id)
        .map_or_else(GrantSet::empty, |grants| GrantSet::from_api(grants));
    if grants.allows(capability, wall_now().0) {
        authorize_resource_scope(state, request, principal_id, capability)?;
        if request.service == "TokenService" {
            match request.method.as_str() {
                "CreateToken" => authorize_token_delegation(state, request, principal_id),
                "ListGrants" | "RevokeToken" => {
                    authorize_token_target(state, request, principal_id)
                }
                _ => Ok(()),
            }
        } else {
            Ok(())
        }
    } else {
        Err(api::StatusCode::PermissionDenied as i32)
    }
}

/// Token grants are principal-owned. A caller may inspect/revoke its own
/// record; managing another principal requires an explicit `all_resources`
/// `TokenAdmin` grant so a normal delegated token cannot enumerate or revoke
/// unrelated credentials.
fn authorize_token_target(
    state: &RuntimeState,
    request: &api::Request,
    issuer_principal: u64,
) -> Result<(), i32> {
    let target_principal = match request.method.as_str() {
        "ListGrants" => {
            let Ok(list) = api::ListGrantsRequest::decode(request.payload.as_slice()) else {
                return Err(api::StatusCode::InvalidArgument as i32);
            };
            parse_principal_id(&list.principal_id)?
        }
        "RevokeToken" => {
            let Ok(revoke) = api::RevokeTokenRequest::decode(request.payload.as_slice()) else {
                return Err(api::StatusCode::InvalidArgument as i32);
            };
            parse_principal_id(&revoke.token_id)?
        }
        _ => return Ok(()),
    };
    if target_principal == 0 || target_principal == issuer_principal {
        return Ok(());
    }
    let administrative = state
        .token_grants
        .get(&issuer_principal)
        .into_iter()
        .flatten()
        .any(|grant| {
            grant.capability == api::Capability::TokenAdmin as i32
                && grant.expires_at_unix_ms >= 0
                && (grant.expires_at_unix_ms == 0
                    || u64::try_from(grant.expires_at_unix_ms)
                        .is_ok_and(|expiry| wall_now().0 < expiry))
                && grant
                    .constraints
                    .as_ref()
                    .is_some_and(|constraints| constraints.all_resources)
        });
    administrative
        .then_some(())
        .ok_or(api::StatusCode::PermissionDenied as i32)
}

fn parse_principal_id(bytes: &[u8]) -> Result<u64, i32> {
    if bytes.is_empty() {
        return Ok(0);
    }
    <[u8; 8]>::try_from(bytes)
        .map(u64::from_be_bytes)
        .map_err(|_| api::StatusCode::InvalidArgument as i32)
}

/// Enforce resource constraints before a live service sees a bearer request.
///
/// The v1 grant wire format carries endpoint identifiers, while several
/// service records still lack durable owner fields. For those methods this
/// helper returns an empty resource set, which means a constrained grant is
/// denied until the service can prove ownership; unrestricted grants continue
/// to work. This is deliberately safer than returning an unfiltered list.
fn authorize_resource_scope(
    state: &RuntimeState,
    request: &api::Request,
    principal_id: u64,
    capability: api::Capability,
) -> Result<(), i32> {
    let Some(resource_ids) = resource_ids_for_request(state, request)? else {
        return Ok(());
    };
    let grants = state
        .token_grants
        .get(&principal_id)
        .map_or_else(GrantSet::empty, |grants| GrantSet::from_api(grants));
    let now_ms = wall_now().0;
    let allowed = if resource_ids.is_empty() {
        grants.resource_allowed(capability, &[], now_ms)
    } else {
        resource_ids
            .iter()
            .all(|resource| grants.resource_allowed(capability, resource, now_ms))
    };
    if allowed {
        Ok(())
    } else {
        Err(api::StatusCode::PermissionDenied as i32)
    }
}

/// Extract endpoint-like resource identifiers from requests that have a
/// stable v1 representation. `Some(empty)` means the method is resource
/// bearing but did not identify an owned resource, so constrained grants must
/// fail closed. `None` means the method is node-wide or has no modeled
/// resource scope yet.
#[allow(clippy::too_many_lines)]
fn resource_ids_for_request(
    state: &RuntimeState,
    request: &api::Request,
) -> Result<Option<Vec<Vec<u8>>>, i32> {
    let invalid = || Err(api::StatusCode::InvalidArgument as i32);
    match (request.service.as_str(), request.method.as_str()) {
        ("PeerService", "ListPeers") => {
            if api::ListPeersRequest::decode(request.payload.as_slice()).is_err() {
                return invalid();
            }
            Ok(Some(Vec::new()))
        }
        ("PeerService", "GetPeer") => {
            let Ok(get) = api::GetPeerRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(vec![get.endpoint_id]))
        }
        ("PeerService", "AddPeerHint") => {
            let Ok(add) = api::AddPeerHintRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(vec![add.endpoint_id]))
        }
        ("PeerService", "RemovePeer") => {
            let Ok(remove) = api::RemovePeerRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(vec![remove.endpoint_id]))
        }
        ("PeerService", "SetTrustState") => {
            let Ok(set) = api::SetTrustStateRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(vec![set.endpoint_id]))
        }
        ("PeerService", "BlockPeer") => {
            let Ok(block) = api::BlockPeerRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(vec![block.endpoint_id]))
        }
        ("PeerService", "UnblockPeer") => {
            let Ok(unblock) = api::UnblockPeerRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(vec![unblock.endpoint_id]))
        }
        ("SessionService", "ListSessions") => {
            let Ok(list) = api::ListSessionsRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(if list.endpoint_id.is_empty() {
                Vec::new()
            } else {
                vec![list.endpoint_id]
            }))
        }
        ("SessionService", "GetSession") => {
            let Ok(get) = api::GetSessionRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            session_resource_id(state, get.session_handle.as_ref())
        }
        ("SessionService", "CloseSession") => {
            let Ok(close) = api::CloseSessionRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            session_resource_id(state, close.session_handle.as_ref())
        }
        ("SessionService", "MigrateSession") => {
            let Ok(migrate) = api::MigrateSessionRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            session_resource_id(state, migrate.session_handle.as_ref())
        }
        ("SessionService", "ListStreams") => {
            let Ok(list) = api::ListStreamsRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            session_resource_id(state, list.session_handle.as_ref())
        }
        ("RouteService", "ListRoutes") => {
            let Ok(list) = api::ListRoutesRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(if list.destination_hint_hash.is_empty() {
                Vec::new()
            } else {
                vec![list.destination_hint_hash]
            }))
        }
        ("RouteService", "GetRoute") => {
            let Ok(get) = api::GetRouteRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(vec![get
                .route_handle
                .map(|handle| handle.value)
                .unwrap_or_default()]))
        }
        ("RouteService", "ProbeRoute") => {
            let Ok(probe) = api::ProbeRouteRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(vec![probe.destination_hint]))
        }
        ("RouteService", "InvalidateRoute") => {
            let Ok(invalidate) = api::InvalidateRouteRequest::decode(request.payload.as_slice())
            else {
                return invalid();
            };
            Ok(Some(vec![invalidate
                .route_handle
                .map(|handle| handle.value)
                .unwrap_or_default()]))
        }
        ("BundleService", "ListBundles" | "GetBundles") => {
            let Ok(list) = api::ListBundlesRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(if list.owner_endpoint_id.is_empty() {
                Vec::new()
            } else {
                vec![list.owner_endpoint_id]
            }))
        }
        ("BundleService", "GetBundle") => {
            if api::GetBundleRequest::decode(request.payload.as_slice()).is_err() {
                return invalid();
            }
            Ok(Some(Vec::new()))
        }
        ("BundleService", "DeleteBundle") => {
            if api::DeleteBundleRequest::decode(request.payload.as_slice()).is_err() {
                return invalid();
            }
            Ok(Some(Vec::new()))
        }
        ("RelayService", "ListRelayCircuits") => {
            if api::ListRelayCircuitsRequest::decode(request.payload.as_slice()).is_err() {
                return invalid();
            }
            Ok(Some(Vec::new()))
        }
        ("RelayService", "CloseRelayCircuit") => {
            if api::CloseRelayCircuitRequest::decode(request.payload.as_slice()).is_err() {
                return invalid();
            }
            Ok(Some(Vec::new()))
        }
        ("EventService", "Subscribe") => {
            let Ok(subscribe) = api::SubscribeRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(
                subscribe
                    .filter
                    .map(|filter| filter.endpoint_ids)
                    .unwrap_or_default(),
            ))
        }
        ("ApplicationService", "RegisterApplication") => {
            let Ok(register) = api::RegisterApplicationRequest::decode(request.payload.as_slice())
            else {
                return invalid();
            };
            Ok(Some(register.requested_endpoint_ids))
        }
        ("ApplicationService", "OpenListener") => {
            let Ok(open) = api::OpenListenerRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            Ok(Some(if open.endpoint_id.is_empty() {
                Vec::new()
            } else {
                vec![open.endpoint_id]
            }))
        }
        ("IdentityService", "ListIdentities") => {
            if api::ListIdentitiesRequest::decode(request.payload.as_slice()).is_err() {
                return invalid();
            }
            Ok(Some(Vec::new()))
        }
        ("IdentityService", "GetIdentity") => {
            let Ok(get) = api::GetIdentityRequest::decode(request.payload.as_slice()) else {
                return invalid();
            };
            let resource = match get.identity {
                Some(api::get_identity_request::Identity::EndpointId(endpoint)) => endpoint,
                Some(api::get_identity_request::Identity::Handle(handle)) => state
                    .identity_by_handle(&handle.value)
                    .map(|resolved| match resolved {
                        crate::state::IdentityRef::Primary => state.node_identity.endpoint_id(),
                        crate::state::IdentityRef::Secondary(entry) => entry.identity.endpoint_id(),
                    })
                    .map(|endpoint| endpoint.to_vec())
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            Ok(Some(vec![resource]))
        }
        _ => Ok(None),
    }
}

fn session_resource_id(
    state: &RuntimeState,
    handle: Option<&api::OpaqueHandle>,
) -> Result<Option<Vec<Vec<u8>>>, i32> {
    let Some(handle) = handle else {
        return Err(api::StatusCode::InvalidArgument as i32);
    };
    let Ok(bytes) = <[u8; 8]>::try_from(handle.value.as_slice()) else {
        return Err(api::StatusCode::InvalidArgument as i32);
    };
    let session_id = u64::from_be_bytes(bytes);
    let resource = state
        .sessions
        .lookup(session_id)
        .map(|entry| entry.peer_endpoint_id.to_vec())
        .unwrap_or_default();
    Ok(Some(vec![resource]))
}

/// Enforce the non-expansion rule for delegated token grants. A token may
/// delegate only capabilities marked `delegable`, with an expiry no later than
/// the issuer's grant. Constrained grants must retain the issuer's exact
/// resource scope unless the issuer explicitly has `all_resources`.
fn authorize_token_delegation(
    state: &RuntimeState,
    request: &api::Request,
    issuer_principal: u64,
) -> Result<(), i32> {
    let Ok(create) = api::CreateTokenRequest::decode(request.payload.as_slice()) else {
        return Err(api::StatusCode::InvalidArgument as i32);
    };
    if create.expires_at_unix_ms < 0 {
        return Err(api::StatusCode::InvalidArgument as i32);
    }
    let issuer_grants = state
        .token_grants
        .get(&issuer_principal)
        .map_or(&[][..], Vec::as_slice);
    let now_ms = wall_now().0;
    let now_ms_i64 = i64::try_from(now_ms).unwrap_or(i64::MAX);
    for grant in &create.grants {
        let capability = api::Capability::try_from(grant.capability).ok();
        if capability.is_none() || capability == Some(api::Capability::Unspecified) {
            return Err(api::StatusCode::InvalidArgument as i32);
        }
        if grant.expires_at_unix_ms < 0
            || (grant.expires_at_unix_ms > 0
                && create.expires_at_unix_ms > 0
                && grant.expires_at_unix_ms > create.expires_at_unix_ms)
            || !issuer_grants.iter().any(|issuer| {
                issuer.capability == grant.capability
                    && issuer.delegable
                    && issuer.expires_at_unix_ms >= 0
                    && expiry_covers(issuer.expires_at_unix_ms, grant.expires_at_unix_ms)
                    && constraints_cover(issuer.constraints.as_ref(), grant.constraints.as_ref())
                    && (issuer.expires_at_unix_ms == 0 || issuer.expires_at_unix_ms > now_ms_i64)
            })
        {
            return Err(api::StatusCode::PermissionDenied as i32);
        }
    }
    Ok(())
}

fn expiry_covers(issuer_expiry: i64, requested_expiry: i64) -> bool {
    issuer_expiry == 0 || (requested_expiry != 0 && requested_expiry <= issuer_expiry)
}

fn constraints_cover(
    issuer: Option<&api::ResourceConstraints>,
    requested: Option<&api::ResourceConstraints>,
) -> bool {
    match (issuer, requested) {
        (None, _) => true,
        (Some(issuer), Some(requested)) => issuer.all_resources || issuer == requested,
        (Some(issuer), None) => issuer.all_resources,
    }
}

/// Resolve a stable bearer-token principal for page-token binding and grant
/// inspection. Invalid or absent credentials remain the anonymous principal.
pub(crate) fn control_principal_id(
    state: &RuntimeState,
    presented_token: Option<&[u8]>,
) -> Option<u64> {
    presented_token.and_then(|token| state.token_registry.authenticate(token, wall_now().0).ok())
}
