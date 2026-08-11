//! `EventService` request handling and event-stream delivery.
//!
//! This module owns the connection-scoped event subscription behavior. It
//! deliberately returns service status/payload pairs so the control transport
//! and the general dispatcher can keep envelope framing in one place.

use crate::control_transport::ConnectionState;
use crate::control_authorization::control_principal_id;
use crate::event_log::to_control_event;
use crate::state::RuntimeState;
use prost::Message;
use umc_control::events::{
    event_filter_digest, EventHistoryError, EventResumeCursor, EVENT_CURSOR_TTL_MS,
};
use umc_control::proto::umc::api::v1 as api;

/// Dispatch one `EventService` request and return its protocol status/payload.
pub(crate) fn dispatch_request(
    conn: &mut ConnectionState,
    state: &mut RuntimeState,
    request: &api::Request,
    presented_token: Option<&[u8]>,
) -> (i32, Option<Vec<u8>>) {
    if let Some(configured) = &state.development_token {
        let authorized = presented_token.is_some_and(|token| token == configured.as_slice());
        if !authorized {
            return (api::StatusCode::Unauthenticated as i32, None);
        }
    }
    match request.method.as_str() {
        "Subscribe" => subscribe(conn, state, request),
        "Unsubscribe" => unsubscribe(conn, state, request),
        _ => (api::StatusCode::Unimplemented as i32, None),
    }
}

fn subscribe(
    conn: &mut ConnectionState,
    state: &mut RuntimeState,
    request: &api::Request,
) -> (i32, Option<Vec<u8>>) {
    let Ok(subscribe) = api::SubscribeRequest::decode(request.payload.as_slice()) else {
        return (api::StatusCode::InvalidArgument as i32, None);
    };
    if conn.subscriptions.len() >= umc_control::events::MAX_EVENT_STREAMS_PER_CLIENT {
        return (api::StatusCode::ResourceExhausted as i32, None);
    }
    let filter = subscribe.filter.unwrap_or_default();
    let principal_id = control_principal_id(state, conn.presented_token.as_deref()).unwrap_or(0);
    let filter_digest = event_filter_digest(&filter);
    let now_ms = crate::state::wall_now().0;
    let resume_sequence = if subscribe.resume_cursor.is_empty() {
        None
    } else {
        let Some(cursor) = EventResumeCursor::decode(
            &subscribe.resume_cursor,
            &state.event_cursor_key,
        ) else {
            return out_of_range_response();
        };
        if !cursor.validate(
            principal_id,
            state.server_instance_id,
            filter_digest,
            now_ms,
        ) {
            return out_of_range_response();
        }
        Some(cursor.sequence())
    };
    let initial = if resume_sequence.is_none() && filter.include_initial_snapshot {
        Some(state.events.lock().expect("event log").recent(100))
    } else {
        None
    };
    let subscription_id = {
        let mut bus = state.event_bus.lock().expect("event bus");
        let replay = match resume_sequence {
            Some(sequence) => match bus.history_after(sequence) {
                Ok(history) => Some(history),
                Err(EventHistoryError::OutOfRange) => return out_of_range_response(),
            },
            None => None,
        };
        let id = bus.subscribe();
        if let Some(initial) = initial {
            if let Some(subscription) = bus.subscription(id) {
                for event in initial.into_iter().rev() {
                    let _ = subscription.push(to_control_event(&event));
                }
            }
        }
        if let Some(replay) = replay {
            if let Some(subscription) = bus.subscription(id) {
                for (journal_sequence, event) in replay {
                    let _ = subscription.push_with_journal_sequence(event, journal_sequence);
                }
            }
        }
        id
    };
    conn.subscriptions.insert(subscription_id, filter);
    let handle = subscription_id.to_be_bytes().to_vec();
    let resume_cursor = make_cursor(
        principal_id,
        state.server_instance_id,
        filter_digest,
        state
            .event_bus
            .lock()
            .expect("event bus")
            .latest_event_sequence(),
        now_ms,
        &state.event_cursor_key,
    );
    let response = api::SubscribeResponse {
        subscription_handle: Some(api::OpaqueHandle {
            value: handle.clone(),
        }),
        resume_cursor,
        first_event_sequence: 1,
    };
    let mut payload = Vec::new();
    Message::encode(&response, &mut payload).expect("encode");
    (api::StatusCode::Ok as i32, Some(payload))
}

fn out_of_range_response() -> (i32, Option<Vec<u8>>) {
    let payload = api::EventGap {
        snapshot_required: true,
        ..Default::default()
    }
    .encode_to_vec();
    (api::StatusCode::OutOfRange as i32, Some(payload))
}

fn make_cursor(
    principal_id: u64,
    generation: [u8; 16],
    filter_digest: [u8; 16],
    sequence: u64,
    now_ms: u64,
    key: &[u8; 32],
) -> Vec<u8> {
    EventResumeCursor::encode(
        principal_id,
        generation,
        filter_digest,
        sequence,
        now_ms.saturating_add(EVENT_CURSOR_TTL_MS),
        key,
    )
}

fn unsubscribe(
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

/// Drain queued events for every live subscription on a connection.
pub(crate) fn drain_event_envelopes(
    state: &mut RuntimeState,
    conn: &mut ConnectionState,
) -> Vec<api::Envelope> {
    let subscriptions: Vec<(u64, api::EventFilter)> = conn
        .subscriptions
        .iter()
        .map(|(id, filter)| (*id, filter.clone()))
        .collect();
    let mut bus = state.event_bus.lock().expect("event bus");
    let latest_journal_sequence = bus.latest_event_sequence();
    let mut envelopes = Vec::new();
    for (id, filter) in subscriptions {
        let Some(subscription) = bus.subscription(id) else {
            continue;
        };
        if let Some((first_missing_sequence, last_missing_sequence)) = subscription.take_event_gap()
        {
            let gap = api::EventGap {
                first_missing_sequence,
                last_missing_sequence,
                snapshot_required: true,
            };
            envelopes.push(api::Envelope {
                api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
                sequence: conn.next_server_sequence(),
                body: Some(api::envelope::Body::Event(api::Event {
                    subscription_handle: Some(api::OpaqueHandle {
                        value: id.to_be_bytes().to_vec(),
                    }),
                    event_sequence: first_missing_sequence,
                    event_type: api::EventType::EventGap as i32,
                    event_class: api::EventClass::Critical as i32,
                    occurred_at_unix_ms: i64::try_from(crate::state::wall_now().0)
                        .unwrap_or(i64::MAX),
                    payload_type: "event_gap".into(),
                    payload: gap.encode_to_vec(),
                    resume_cursor: make_cursor(
                        control_principal_id(state, conn.presented_token.as_deref()).unwrap_or(0),
                        state.server_instance_id,
                        event_filter_digest(&filter),
                        latest_journal_sequence,
                        crate::state::wall_now().0,
                        &state.event_cursor_key,
                    ),
                    ..Default::default()
                })),
            });
        }
        while let Some((sequence, journal_sequence, event)) =
            subscription.pop_with_sequence_and_journal()
        {
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
                    resume_cursor: make_cursor(
                        control_principal_id(state, conn.presented_token.as_deref()).unwrap_or(0),
                        state.server_instance_id,
                        event_filter_digest(&filter),
                        if journal_sequence == 0 {
                            latest_journal_sequence
                        } else {
                            journal_sequence
                        },
                        crate::state::wall_now().0,
                        &state.event_cursor_key,
                    ),
                })),
            });
        }
    }
    envelopes
}

/// Apply a client acknowledgement to a subscription owned by this
/// connection. Unknown or malformed handles are deliberately silent: event
/// acknowledgements are flow-control hints, not request/response RPCs.
pub(crate) fn acknowledge_event(
    state: &mut RuntimeState,
    conn: &ConnectionState,
    ack: &api::EventAck,
) {
    let Some(handle) = ack.subscription_handle.as_ref() else {
        return;
    };
    let Ok(id_bytes) = <[u8; 8]>::try_from(handle.value.as_slice()) else {
        return;
    };
    let id = u64::from_be_bytes(id_bytes);
    if !conn.subscriptions.contains_key(&id) {
        return;
    }
    if let Some(subscription) = state.event_bus.lock().expect("event bus").subscription(id) {
        subscription.ack(ack.highest_contiguous_sequence);
    }
}

fn event_matches_filter(event: &umc_control::events::UmpEvent, filter: &api::EventFilter) -> bool {
    let event_type = event_type_code(&event.event_type);
    if !filter.event_types.is_empty() && !filter.event_types.contains(&event_type) {
        return false;
    }
    if !filter.resource_handles.is_empty() {
        let Some(resource) = event.resource.as_ref() else {
            return false;
        };
        if !filter
            .resource_handles
            .iter()
            .any(|handle| handle.value == *resource)
        {
            return false;
        }
    }
    if !filter.endpoint_ids.is_empty() {
        let Some(resource) = event.resource.as_ref() else {
            return false;
        };
        if !filter
            .endpoint_ids
            .iter()
            .any(|endpoint| endpoint == resource)
        {
            return false;
        }
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
        "session_active" | "session_suspended" | "session_closing" | "session_closed" => {
            api::EventType::SessionState as i32
        }
        "path_added" | "path_validated" | "path_degraded" | "path_failed" | "path_retired"
        | "path_migrated" | "carrier_changed" => api::EventType::PathChanged as i32,
        "stream_bytes_accepted" | "stream_bytes_lost" | "stream_reset" | "stream_stopped" => {
            api::EventType::StreamState as i32
        }
        "bundle_admitted" | "bundle_expired" => api::EventType::BundleState as i32,
        "circuit_opened" | "circuit_closed" | "relay_data_forwarded" => {
            api::EventType::RelayState as i32
        }
        "application_registered"
        | "application_unregistered"
        | "carrier_instance_created"
        | "carrier_instance_updated"
        | "carrier_instance_started"
        | "carrier_instance_stopped"
        | "carrier_instance_deleted" => api::EventType::NodeState as i32,
        "peer_blocked" | "peer_unblocked" | "trust_state_set" => api::EventType::PeerChanged as i32,
        _ => api::EventType::Audit as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_path_and_session_events_use_stable_event_classes() {
        for kind in [
            "path_added",
            "path_validated",
            "path_degraded",
            "path_failed",
            "path_retired",
            "path_migrated",
            "carrier_changed",
        ] {
            assert_eq!(event_type_code(kind), api::EventType::PathChanged as i32);
        }
        for kind in [
            "session_active",
            "session_suspended",
            "session_closing",
            "session_closed",
        ] {
            assert_eq!(event_type_code(kind), api::EventType::SessionState as i32);
        }
    }

    fn event(resource: Option<Vec<u8>>) -> umc_control::events::UmpEvent {
        umc_control::events::UmpEvent {
            class: umc_control::events::EventClass::State,
            event_type: "session_active".into(),
            resource,
            payload: Vec::new(),
            occurred_at_ms: 1,
        }
    }

    #[test]
    fn resource_and_endpoint_filters_match_visible_resource_ids() {
        let resource = b"resource".to_vec();
        let resource_filter = api::EventFilter {
            resource_handles: vec![api::OpaqueHandle {
                value: resource.clone(),
            }],
            ..Default::default()
        };
        assert!(event_matches_filter(
            &event(Some(resource.clone())),
            &resource_filter
        ));
        assert!(!event_matches_filter(
            &event(Some(b"other".to_vec())),
            &resource_filter
        ));

        let endpoint_filter = api::EventFilter {
            endpoint_ids: vec![resource.clone()],
            ..Default::default()
        };
        assert!(event_matches_filter(
            &event(Some(resource)),
            &endpoint_filter
        ));
    }
}
