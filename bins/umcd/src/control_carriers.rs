//! Registry-backed `CarrierService` instance lifecycle.
//!
//! The carrier trait is intentionally small: concrete carriers expose
//! `listen`/`dial`, but they do not expose a generic factory or a separate
//! start/stop object. This module therefore owns the control-plane instance
//! records and their optimistic lifecycle state. Startup wiring registers the
//! concrete built-ins; dynamically-created records are validated against that
//! registry and can acquire a concrete listener when a `bind_address` option
//! is supplied. The carrier trait remains the boundary for dialing and link
//! ownership.

use crate::runtime_adapters::OsEntropy;
use crate::server::{page_info, page_window, push_event};
use crate::state::RuntimeState;
use prost::Message;
use std::sync::Arc;
use umc_carrier::error::CarrierErrorKind;
use umc_carrier::Listener;
use umc_control::proto::umc::api::v1 as api;
use umc_types::runtime::EntropySource;

pub(crate) const CARRIER_HANDLE_LEN: usize = 16;

/// Control-plane state for one carrier instance.
#[derive(Debug, Clone)]
pub struct CarrierInstanceRecord {
    pub handle: Vec<u8>,
    pub type_id: String,
    pub label: String,
    pub state: i32,
    pub options: Vec<api::ConfigEntry>,
    pub revision: u64,
    pub external_plugin: bool,
    pub isolation_state: String,
}

/// Register the concrete carriers wired during daemon startup as running
/// instance records. A carrier type has one stable boot-time instance in the
/// current runtime; control-created records remain distinct metadata records.
pub(crate) fn register_static_instances(state: &mut RuntimeState) {
    state.carrier_registry_initialized = true;
    let configured: Vec<String> = state
        .config
        .carriers
        .iter()
        .filter(|type_id| {
            !state.config.carrier_disabled(type_id) && state.node.carrier(type_id).is_some()
        })
        .cloned()
        .collect();
    for type_id in configured {
        if state
            .carrier_instances
            .values()
            .any(|instance| instance.type_id == type_id)
        {
            continue;
        }
        let handle = allocate_handle(state);
        state.carrier_instances.insert(
            handle.clone(),
            CarrierInstanceRecord {
                handle,
                type_id: type_id.clone(),
                label: type_id.clone(),
                state: api::CarrierInstanceState::Running as i32,
                options: Vec::new(),
                revision: 1,
                external_plugin: false,
                isolation_state: "in-process".into(),
            },
        );
        push_event(
            state,
            "carrier_instance_started",
            format!("static carrier instance {type_id} started"),
        );
    }
}

/// Whether control-plane operations may use at least one running instance of
/// a carrier type. The uninitialized-registry fallback preserves the type-only
/// v1 `Listen` tests and legacy callers until startup wiring has materialized
/// the instance records.
#[must_use]
pub(crate) fn type_is_running(state: &RuntimeState, type_id: &str) -> bool {
    !state.carrier_registry_initialized
        || state.carrier_instances.values().any(|instance| {
            instance.type_id == type_id
                && instance_state(instance) == api::CarrierInstanceState::Running
        })
}

/// Dispatch the lifecycle methods that have a control-plane registry backing.
pub(crate) fn dispatch_request(
    state: &mut RuntimeState,
    request: &api::Request,
    principal_id: u64,
) -> (i32, Option<Vec<u8>>) {
    match request.method.as_str() {
        "ListCarrierInstances" => list_instances(state, request, principal_id),
        "GetCarrierInstance" => get_instance(state, request),
        "CreateCarrierInstance" => create_instance(state, request),
        "UpdateCarrierInstance" => update_instance(state, request),
        "StartCarrier" => start_carrier(state, request),
        "StopCarrier" => stop_carrier(state, request),
        "DeleteCarrierInstance" => delete_instance(state, request),
        _ => (api::StatusCode::Unimplemented as i32, None),
    }
}

fn list_instances(
    state: &RuntimeState,
    request: &api::Request,
    principal_id: u64,
) -> (i32, Option<Vec<u8>>) {
    let Ok(list) = api::ListCarrierInstancesRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Ok((offset, page_size)) = page_window(
        list.page.as_ref(),
        "ListCarrierInstances",
        principal_id,
        &state.ticket_key,
    ) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let mut all: Vec<&CarrierInstanceRecord> = state.carrier_instances.values().collect();
    all.sort_by(|left, right| left.handle.cmp(&right.handle));
    let total = all.len();
    let instances = all
        .into_iter()
        .skip(offset)
        .take(page_size)
        .map(instance_message)
        .collect();
    let response = api::ListCarrierInstancesResponse {
        instances,
        page: Some(page_info(
            total,
            offset,
            page_size,
            "ListCarrierInstances",
            principal_id,
            &state.ticket_key,
        )),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode carrier instance list");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn get_instance(state: &RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(get) = api::GetCarrierInstanceRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = valid_handle(get.carrier_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(instance) = state.carrier_instances.get(handle) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let response = api::GetCarrierInstanceResponse {
        instance: Some(instance_message(instance)),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode carrier instance");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn create_instance(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(create) = api::CreateCarrierInstanceRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if create.type_id.is_empty() {
        return (api::StatusCode::InvalidArgument as i32, None);
    }
    if state.node.carrier(&create.type_id).is_none() {
        return (api::StatusCode::NotFound as i32, None);
    }
    let Ok(options) = materialize_options(&create.options, Vec::new()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    state.carrier_registry_initialized = true;
    let type_id = create.type_id.clone();
    let handle = allocate_handle(state);
    let instance = CarrierInstanceRecord {
        handle: handle.clone(),
        type_id: type_id.clone(),
        label: if create.label.is_empty() {
            type_id.clone()
        } else {
            create.label
        },
        state: if create.enabled {
            api::CarrierInstanceState::Created as i32
        } else {
            api::CarrierInstanceState::Disabled as i32
        },
        options,
        revision: 1,
        external_plugin: false,
        isolation_state: "in-process".into(),
    };
    let message = instance_message(&instance);
    state.carrier_instances.insert(handle, instance);
    push_event(
        state,
        "carrier_instance_created",
        format!("{type_id} carrier instance created"),
    );
    let response = api::CreateCarrierInstanceResponse {
        instance: Some(message),
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode created carrier instance");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn update_instance(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(update) = api::UpdateCarrierInstanceRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = valid_handle(update.carrier_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(instance) = state.carrier_instances.get_mut(handle) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if let Some(expected) = update.expected_revision {
        if expected.value != instance.revision {
            return (api::StatusCode::Conflict as i32, None);
        }
    }
    if update.options.is_empty() {
        let response = api::UpdateCarrierInstanceResponse {
            instance: Some(instance_message(instance)),
            effects: Vec::new(),
        };
        let mut payload = Vec::new();
        Message::encode(&response, &mut payload).expect("encode unchanged carrier instance");
        return (api::StatusCode::Ok as i32, Some(payload));
    }
    let Ok(options) = materialize_options(&update.options, instance.options.clone()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    instance.options = options;
    instance.revision = instance.revision.saturating_add(1);
    let event_detail = format!("carrier instance {:?} options updated", instance.handle);
    let response = api::UpdateCarrierInstanceResponse {
        instance: Some(instance_message(instance)),
        effects: vec![api::ConfigEffect {
            subsystem: "carrier".into(),
            restart_required: true,
            drain_required: false,
            message: "carrier options updated; restart required to apply runtime changes".into(),
        }],
    };
    push_event(state, "carrier_instance_updated", event_detail);
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode updated carrier instance");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn start_carrier(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(start) = api::StartCarrierRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = valid_handle(start.carrier_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let handle_key = handle.to_vec();
    let Some(instance) = state.carrier_instances.get(handle) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let current = instance_state(instance);
    if current == api::CarrierInstanceState::Disabled {
        return (api::StatusCode::FailedPrecondition as i32, None);
    }
    let type_id = instance.type_id.clone();
    let options = instance.options.clone();
    if state.node.carrier(&type_id).is_none() {
        if let Some(instance) = state.carrier_instances.get_mut(handle) {
            instance.state = api::CarrierInstanceState::Failed as i32;
            instance.revision = instance.revision.saturating_add(1);
        }
        return (api::StatusCode::FailedPrecondition as i32, None);
    }
    let resource_started = match start_listener(state, &handle_key, &type_id, &options) {
        Ok(started) => started,
        Err(status) => {
            if let Some(instance) = state.carrier_instances.get_mut(handle) {
                instance.state = api::CarrierInstanceState::Failed as i32;
                instance.revision = instance.revision.saturating_add(1);
            }
            return (status, None);
        }
    };
    let started = current != api::CarrierInstanceState::Running || resource_started;
    let event_detail = if started {
        Some(format!("carrier instance {handle_key:?} started"))
    } else {
        None
    };
    let response_instance = {
        let instance = state
            .carrier_instances
            .get_mut(handle)
            .expect("carrier instance checked above");
        if started {
            instance.state = api::CarrierInstanceState::Running as i32;
            instance.revision = instance.revision.saturating_add(1);
        }
        instance_message(instance)
    };
    let response = api::StartCarrierResponse {
        instance: Some(response_instance),
    };
    if let Some(event_detail) = event_detail {
        push_event(state, "carrier_instance_started", event_detail);
    }
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode started carrier instance");
    (api::StatusCode::Ok as i32, Some(payload))
}

/// Starts a concrete listener for a control-created instance when its public
/// options contain a bind address. Instances without a bind option retain the
/// metadata-only behavior required for discovery-only and externally managed
/// carrier profiles.
fn start_listener(
    state: &mut RuntimeState,
    handle: &[u8],
    type_id: &str,
    options: &[api::ConfigEntry],
) -> Result<bool, i32> {
    let Some(bind_address) = option_value(options, "bind_address")
        .or_else(|| option_value(options, "address"))
        .or_else(|| option_value(options, "listen"))
    else {
        return Ok(false);
    };
    if bind_address.trim().is_empty() {
        return Err(api::StatusCode::InvalidArgument as i32);
    }
    if state.carrier_listeners.contains_key(handle) {
        return Ok(false);
    }
    // Direct composition-root tests and synchronous callers can exercise the
    // registry without a Tokio runtime. Keep their lifecycle metadata valid;
    // concrete socket acquisition is only possible from the daemon runtime.
    if tokio::runtime::Handle::try_current().is_err() {
        return Ok(false);
    }
    let Some(carrier) = state.node.carrier(type_id) else {
        return Err(api::StatusCode::FailedPrecondition as i32);
    };
    // `Carrier::listen` is a synchronous composition-boundary operation. The
    // built-in carriers bind nonblocking standard sockets, so calling it
    // directly is safe on both Tokio scheduler flavors; `block_in_place`
    // would panic when StartCarrier runs on a current-thread runtime.
    let listener = carrier
        .listen(bind_address.clone())
        .map_err(|error| carrier_error_status(&error))?;
    let listener: Arc<dyn Listener + Send + Sync> = Arc::from(listener);
    state
        .carrier_listeners
        .insert(handle.to_vec(), listener.clone());
    if let Some(runtime) = state.self_arc.upgrade() {
        let carrier_type = type_id.to_string();
        tokio::spawn(async move {
            crate::accept_loop(&runtime, carrier_type, listener).await;
        });
    }
    Ok(true)
}

fn option_value(options: &[api::ConfigEntry], key: &str) -> Option<String> {
    options
        .iter()
        .find(|entry| entry.key == key && !entry.sensitive_present)
        .map(|entry| entry.value.clone())
}

pub(crate) fn carrier_error_status(error: &umc_carrier::error::CarrierError) -> i32 {
    match error.kind {
        CarrierErrorKind::InvalidArgument | CarrierErrorKind::AddressInvalid => {
            api::StatusCode::InvalidArgument as i32
        }
        CarrierErrorKind::AddressInUse
        | CarrierErrorKind::PermissionDenied
        | CarrierErrorKind::NotRunning
        | CarrierErrorKind::Unsupported => api::StatusCode::FailedPrecondition as i32,
        CarrierErrorKind::ResourceLimit | CarrierErrorKind::QueueFull => {
            api::StatusCode::ResourceExhausted as i32
        }
        CarrierErrorKind::Unreachable
        | CarrierErrorKind::DeviceUnavailable
        | CarrierErrorKind::WouldBlock => api::StatusCode::Unavailable as i32,
        _ => api::StatusCode::Internal as i32,
    }
}

fn stop_carrier(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(stop) = api::StopCarrierRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = valid_handle(stop.carrier_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let handle_key = handle.to_vec();
    let Some(instance) = state.carrier_instances.get(handle) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    let current = instance_state(instance);
    if current == api::CarrierInstanceState::Disabled {
        return (api::StatusCode::FailedPrecondition as i32, None);
    }
    let carrier_type = instance.type_id.clone();
    if let Some(listener) = state.carrier_listeners.remove(&handle_key) {
        let _ = listener.close();
    }
    if !stop.drain_links {
        let raw_handles: Vec<Vec<u8>> = state
            .carrier_links
            .iter()
            .filter(|(_, link)| link.carrier_handle == handle_key)
            .map(|(link_handle, _)| link_handle.clone())
            .collect();
        for raw_handle in raw_handles {
            if let Some(link) = state.carrier_links.remove(&raw_handle) {
                let _ = link.link.close("carrier stopped");
            }
        }
        for (session_id, entry) in state.sessions.snapshot() {
            if entry.carrier_type == carrier_type {
                if let Some(control) = state.session_controls.get(&session_id) {
                    control.links.close_all("carrier stopped");
                }
                entry.task.abort();
            }
        }
    }
    let stopped = current != api::CarrierInstanceState::Stopped;
    let event_detail = if stopped {
        Some(format!("carrier instance {handle_key:?} stopped"))
    } else {
        None
    };
    let response_instance = {
        let instance = state
            .carrier_instances
            .get_mut(handle)
            .expect("carrier instance checked above");
        if stopped {
            instance.state = api::CarrierInstanceState::Stopped as i32;
            instance.revision = instance.revision.saturating_add(1);
        }
        instance_message(instance)
    };
    let response = api::StopCarrierResponse {
        instance: Some(response_instance),
    };
    if let Some(event_detail) = event_detail {
        push_event(state, "carrier_instance_stopped", event_detail);
    }
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode stopped carrier instance");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn delete_instance(state: &mut RuntimeState, request: &api::Request) -> (i32, Option<Vec<u8>>) {
    let Ok(delete) = api::DeleteCarrierInstanceRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(handle) = valid_handle(delete.carrier_handle.as_ref()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    let Some(instance) = state.carrier_instances.get(handle) else {
        return (api::StatusCode::NotFound as i32, None);
    };
    if let Some(expected) = delete.expected_revision {
        if expected.value != instance.revision {
            return (api::StatusCode::Conflict as i32, None);
        }
    }
    match instance_state(instance) {
        api::CarrierInstanceState::Running
        | api::CarrierInstanceState::Starting
        | api::CarrierInstanceState::Stopping
        | api::CarrierInstanceState::Degraded => {
            return (api::StatusCode::FailedPrecondition as i32, None);
        }
        api::CarrierInstanceState::Unspecified
        | api::CarrierInstanceState::Created
        | api::CarrierInstanceState::Stopped
        | api::CarrierInstanceState::Failed
        | api::CarrierInstanceState::Disabled => {}
    }
    if state
        .carrier_links
        .values()
        .any(|link| link.carrier_handle == handle)
    {
        return (api::StatusCode::FailedPrecondition as i32, None);
    }
    state.carrier_instances.remove(handle);
    push_event(
        state,
        "carrier_instance_deleted",
        format!("carrier instance {handle:?} deleted"),
    );
    let mut payload = Vec::new();
    Message::encode(&api::DeleteCarrierInstanceResponse {}, &mut payload)
        .expect("encode deleted carrier instance");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn instance_message(instance: &CarrierInstanceRecord) -> api::CarrierInstance {
    api::CarrierInstance {
        carrier_handle: Some(api::OpaqueHandle {
            value: instance.handle.clone(),
        }),
        type_id: instance.type_id.clone(),
        label: instance.label.clone(),
        state: instance.state,
        options: instance.options.clone(),
        revision: Some(api::ResourceRevision {
            value: instance.revision,
        }),
        external_plugin: instance.external_plugin,
        isolation_state: instance.isolation_state.clone(),
    }
}

pub(crate) fn instance_state(instance: &CarrierInstanceRecord) -> api::CarrierInstanceState {
    api::CarrierInstanceState::try_from(instance.state)
        .unwrap_or(api::CarrierInstanceState::Unspecified)
}

fn valid_handle(handle: Option<&api::OpaqueHandle>) -> Option<&[u8]> {
    let value = handle?.value.as_slice();
    (value.len() == CARRIER_HANDLE_LEN).then_some(value)
}

fn allocate_handle(state: &RuntimeState) -> Vec<u8> {
    loop {
        let mut handle = vec![0u8; CARRIER_HANDLE_LEN];
        OsEntropy.fill(&mut handle);
        if !state.carrier_instances.contains_key(&handle) {
            return handle;
        }
    }
}

fn materialize_options(
    mutations: &[api::ConfigMutation],
    mut options: Vec<api::ConfigEntry>,
) -> Result<Vec<api::ConfigEntry>, ()> {
    for mutation in mutations {
        if mutation.key.trim().is_empty() {
            return Err(());
        }
        match mutation.operation.as_ref() {
            Some(api::config_mutation::Operation::SetValue(value)) => {
                upsert_option(
                    &mut options,
                    api::ConfigEntry {
                        key: mutation.key.clone(),
                        value: value.clone(),
                        sensitive_present: false,
                    },
                );
            }
            Some(api::config_mutation::Operation::SetSecret(_)) => {
                upsert_option(
                    &mut options,
                    api::ConfigEntry {
                        key: mutation.key.clone(),
                        value: String::new(),
                        sensitive_present: true,
                    },
                );
            }
            Some(api::config_mutation::Operation::Clear(_)) => {
                options.retain(|entry| entry.key != mutation.key);
            }
            None => return Err(()),
        }
    }
    Ok(options)
}

fn upsert_option(options: &mut Vec<api::ConfigEntry>, entry: api::ConfigEntry) {
    if let Some(existing) = options.iter_mut().find(|option| option.key == entry.key) {
        *existing = entry;
    } else {
        options.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialize_options_redacts_secrets_and_applies_clear() {
        let options = materialize_options(
            &[
                api::ConfigMutation {
                    key: "address".into(),
                    operation: Some(api::config_mutation::Operation::SetValue(
                        "127.0.0.1:1".into(),
                    )),
                },
                api::ConfigMutation {
                    key: "password".into(),
                    operation: Some(api::config_mutation::Operation::SetSecret(
                        b"secret".to_vec(),
                    )),
                },
                api::ConfigMutation {
                    key: "address".into(),
                    operation: Some(api::config_mutation::Operation::Clear(true)),
                },
            ],
            Vec::new(),
        )
        .expect("valid mutations");
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].key, "password");
        assert!(options[0].sensitive_present);
        assert!(options[0].value.is_empty());
    }

    #[test]
    fn invalid_option_mutations_fail_closed() {
        assert!(materialize_options(
            &[api::ConfigMutation {
                key: String::new(),
                operation: Some(api::config_mutation::Operation::SetValue("x".into())),
            }],
            Vec::new(),
        )
        .is_err());
        assert!(materialize_options(
            &[api::ConfigMutation {
                key: "missing-op".into(),
                operation: None,
            }],
            Vec::new(),
        )
        .is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn configured_bind_address_creates_and_releases_runtime_listener() {
        let data_dir = std::env::temp_dir().join(format!(
            "umcd-carrier-runtime-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let config = crate::config::NodeConfig {
            data_dir,
            carriers: vec!["ump.tcp/1".into()],
            tcp_listen: None,
            udp_listen: None,
            ..crate::config::NodeConfig::default()
        };
        let (shutdown_tx, _shutdown_rx) = tokio::sync::mpsc::channel(1);
        let mut state = RuntimeState::new(config, shutdown_tx).expect("state");
        state
            .node
            .register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));

        let create = api::CreateCarrierInstanceRequest {
            type_id: "ump.tcp/1".into(),
            label: "runtime-test".into(),
            options: vec![api::ConfigMutation {
                key: "bind_address".into(),
                operation: Some(api::config_mutation::Operation::SetValue(
                    "127.0.0.1:0".into(),
                )),
            }],
            enabled: true,
        };
        let mut create_payload = Vec::new();
        create.encode(&mut create_payload).expect("encode create");
        let create_request = api::Request {
            payload: create_payload,
            ..Default::default()
        };
        let (status, payload) = create_instance(&mut state, &create_request);
        assert_eq!(status, api::StatusCode::Ok as i32);
        let created =
            api::CreateCarrierInstanceResponse::decode(payload.expect("create payload").as_slice())
                .expect("decode create");
        let handle = created
            .instance
            .expect("instance")
            .carrier_handle
            .expect("handle");

        let mut start_payload = Vec::new();
        api::StartCarrierRequest {
            carrier_handle: Some(handle.clone()),
        }
        .encode(&mut start_payload)
        .expect("encode start");
        let start_request = api::Request {
            payload: start_payload,
            ..Default::default()
        };
        let (status, _) = start_carrier(&mut state, &start_request);
        assert_eq!(status, api::StatusCode::Ok as i32);
        assert_eq!(state.carrier_listeners.len(), 1);

        let mut stop_payload = Vec::new();
        api::StopCarrierRequest {
            carrier_handle: Some(handle),
            drain_links: true,
            drain_timeout_ms: 0,
        }
        .encode(&mut stop_payload)
        .expect("encode stop");
        let stop_request = api::Request {
            payload: stop_payload,
            ..Default::default()
        };
        let (status, _) = stop_carrier(&mut state, &stop_request);
        assert_eq!(status, api::StatusCode::Ok as i32);
        assert!(state.carrier_listeners.is_empty());
    }
}
