//! Delivery, path, and lifecycle events (sdk.md §19-20).
#![allow(clippy::missing_errors_doc)]

use prost::Message;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use umc_control::proto::umc::api::v1 as api;

use crate::client::ClientError;
use crate::handles::{GenerationBound, SubscriptionHandle};

/// Transport ownership outcome for reliable stream bytes. None of these
/// variants is an application-level receipt from the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryEvent {
    Acknowledged { stream_id: u64, offset: u64 },
    Lost { stream_id: u64, offset: u64 },
    Reset { stream_id: u64, error_code: u64 },
    Cancelled { stream_id: u64 },
}

impl DeliveryEvent {
    #[must_use]
    pub fn stream_id(&self) -> Option<u64> {
        match self {
            Self::Acknowledged { stream_id, .. }
            | Self::Lost { stream_id, .. }
            | Self::Reset { stream_id, .. }
            | Self::Cancelled { stream_id } => Some(*stream_id),
        }
    }

    #[must_use]
    pub const fn is_application_receipt(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEvent {
    Added { path_id: u64, carrier_type: String },
    Validated { path_id: u64 },
    Degraded { path_id: u64 },
    Failed { path_id: u64 },
    Retired { path_id: u64 },
    Migrated { old_path_id: u64, new_path_id: u64 },
    CarrierChanged { path_id: u64, carrier_type: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Active,
    Suspended,
    Closing { clean: bool },
    Closed { reason: String },
}

/// Principal-scoped filter used by [`crate::Client::subscribe_events`].
///
/// Empty resource and endpoint lists mean "all resources visible to this
/// connection". The daemon intersects these values with the authenticated
/// grant; the embedded backend applies the same filter to its local event
/// stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFilter {
    pub event_types: Vec<api::EventType>,
    pub resource_handles: Vec<Vec<u8>>,
    pub endpoint_ids: Vec<Vec<u8>>,
    pub minimum_severity: api::DiagnosticSeverity,
    pub include_initial_snapshot: bool,
}

impl Default for EventFilter {
    fn default() -> Self {
        Self {
            event_types: Vec::new(),
            resource_handles: Vec::new(),
            endpoint_ids: Vec::new(),
            minimum_severity: api::DiagnosticSeverity::Unspecified,
            include_initial_snapshot: false,
        }
    }
}

impl EventFilter {
    pub(crate) fn to_proto(&self) -> api::EventFilter {
        api::EventFilter {
            event_types: self.event_types.iter().map(|kind| *kind as i32).collect(),
            resource_handles: self
                .resource_handles
                .iter()
                .map(|value| api::OpaqueHandle {
                    value: value.clone(),
                })
                .collect(),
            endpoint_ids: self.endpoint_ids.clone(),
            minimum_severity: self.minimum_severity as i32,
            include_initial_snapshot: self.include_initial_snapshot,
        }
    }
}

/// One event delivered by an `EventService` subscription.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    subscription: SubscriptionHandle,
    sequence: u64,
    event_type: api::EventType,
    event_class: api::EventClass,
    occurred_at_unix_ms: i64,
    resource_handle: Option<Vec<u8>>,
    resource_id: Vec<u8>,
    payload_type: String,
    payload: Vec<u8>,
    resume_cursor: Vec<u8>,
}

impl Event {
    pub(crate) fn from_proto(event: api::Event, generation: u64) -> Result<Self, ClientError> {
        let subscription = event.subscription_handle.ok_or_else(|| {
            ClientError::Proto("event envelope has no subscription handle".into())
        })?;
        Ok(Self {
            subscription: SubscriptionHandle::from_proto_with_generation(&subscription, generation),
            sequence: event.event_sequence,
            event_type: api::EventType::try_from(event.event_type)
                .unwrap_or(api::EventType::Unspecified),
            event_class: api::EventClass::try_from(event.event_class)
                .unwrap_or(api::EventClass::Unspecified),
            occurred_at_unix_ms: event.occurred_at_unix_ms,
            resource_handle: event.resource_handle.map(|handle| handle.value),
            resource_id: event.resource_id,
            payload_type: event.payload_type,
            payload: event.payload,
            resume_cursor: event.resume_cursor,
        })
    }

    #[must_use]
    pub fn subscription(&self) -> &SubscriptionHandle {
        &self.subscription
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn event_type(&self) -> api::EventType {
        self.event_type
    }

    #[must_use]
    pub const fn event_class(&self) -> api::EventClass {
        self.event_class
    }

    #[must_use]
    pub const fn occurred_at_unix_ms(&self) -> i64 {
        self.occurred_at_unix_ms
    }

    #[must_use]
    pub fn resource_handle(&self) -> Option<&[u8]> {
        self.resource_handle.as_deref()
    }

    #[must_use]
    pub fn resource_id(&self) -> &[u8] {
        &self.resource_id
    }

    #[must_use]
    pub fn payload_type(&self) -> &str {
        &self.payload_type
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn resume_cursor(&self) -> &[u8] {
        &self.resume_cursor
    }

    #[must_use]
    pub fn delivery_event(&self) -> Option<DeliveryEvent> {
        let stream_id = self.stream_id_from_event()?;
        match self.payload_type.as_str() {
            "stream_bytes_accepted" => Some(DeliveryEvent::Acknowledged {
                stream_id,
                offset: self.offset_from_event()?,
            }),
            "stream_bytes_lost" => Some(DeliveryEvent::Lost {
                stream_id,
                offset: self.offset_from_event()?,
            }),
            "stream_reset" => Some(DeliveryEvent::Reset {
                stream_id,
                error_code: self.error_from_event()?,
            }),
            "stream_stopped" => Some(DeliveryEvent::Cancelled { stream_id }),
            _ => None,
        }
    }

    #[must_use]
    pub fn path_event(&self) -> Option<PathEvent> {
        let path_id = self.numeric_field("path")?;
        match self.payload_type.as_str() {
            "path_added" => Some(PathEvent::Added {
                path_id,
                carrier_type: self.text_field("carrier").map_or_else(
                    || String::from_utf8_lossy(&self.payload).into_owned(),
                    str::to_owned,
                ),
            }),
            "path_validated" => Some(PathEvent::Validated { path_id }),
            "path_degraded" => Some(PathEvent::Degraded { path_id }),
            "path_failed" => Some(PathEvent::Failed { path_id }),
            "path_retired" => Some(PathEvent::Retired { path_id }),
            "path_migrated" => Some(PathEvent::Migrated {
                old_path_id: path_id,
                new_path_id: self.numeric_field("new_path")?,
            }),
            "carrier_changed" => Some(PathEvent::CarrierChanged {
                path_id,
                carrier_type: self.text_field("carrier").map_or_else(
                    || String::from_utf8_lossy(&self.payload).into_owned(),
                    str::to_owned,
                ),
            }),
            _ => None,
        }
    }

    #[must_use]
    pub fn session_event(&self) -> Option<SessionEvent> {
        match self.payload_type.as_str() {
            "session_active" => Some(SessionEvent::Active),
            "session_suspended" => Some(SessionEvent::Suspended),
            "session_closing" => Some(SessionEvent::Closing {
                clean: self.payload == b"clean",
            }),
            "session_closed" => Some(SessionEvent::Closed {
                reason: String::from_utf8_lossy(&self.payload).into_owned(),
            }),
            _ => None,
        }
    }

    fn stream_id_from_event(&self) -> Option<u64> {
        self.pair_from_event().map(|(stream_id, _)| stream_id)
    }

    fn offset_from_event(&self) -> Option<u64> {
        self.pair_from_event().map(|(_, offset)| offset)
    }

    fn error_from_event(&self) -> Option<u64> {
        self.pair_from_event().map(|(_, error)| error)
    }

    fn pair_from_event(&self) -> Option<(u64, u64)> {
        if self.payload.len() == 16 {
            let stream_id = u64::from_be_bytes(self.payload[..8].try_into().ok()?);
            let value = u64::from_be_bytes(self.payload[8..].try_into().ok()?);
            return Some((stream_id, value));
        }
        let stream_id = self
            .resource_handle
            .as_deref()
            .and_then(handle_u64)
            .or_else(|| self.numeric_field("stream_id"))?;
        let value = self
            .numeric_field("offset")
            .or_else(|| self.numeric_field("error"))?;
        Some((stream_id, value))
    }

    fn numeric_field(&self, name: &str) -> Option<u64> {
        let text = std::str::from_utf8(&self.payload).ok()?;
        let start = text.find(name)?.saturating_add(name.len());
        text[start..]
            .split_whitespace()
            .next()?
            .trim_matches(|character: char| !character.is_ascii_digit())
            .parse()
            .ok()
    }

    fn text_field(&self, name: &str) -> Option<&str> {
        let text = std::str::from_utf8(&self.payload).ok()?;
        let start = text.find(name)?.saturating_add(name.len());
        let value = text[start..].trim_start();
        let end = value.find(char::is_whitespace).unwrap_or(value.len());
        (!value[..end].is_empty()).then_some(&value[..end])
    }
}

fn handle_u64(handle: &[u8]) -> Option<u64> {
    if handle.len() > 8 && handle[..handle.len() - 8].iter().any(|byte| *byte != 0) {
        return None;
    }
    let bytes = handle.get(handle.len().saturating_sub(8)..)?;
    bytes.try_into().ok().map(u64::from_be_bytes)
}

impl GenerationBound for Event {
    fn validate_backend_generation(&self, expected: u64) -> Result<(), ClientError> {
        self.subscription.validate_generation(expected)
    }
}

fn require_ok(response: &api::Response, method: &str) -> Result<(), ClientError> {
    let code = response
        .status
        .as_ref()
        .map_or(api::StatusCode::Ok as i32, |status| status.code);
    if code == api::StatusCode::Ok as i32 {
        Ok(())
    } else {
        Err(ClientError::from_status_for_method(code, method))
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

impl crate::client::Client {
    /// Opens a principal-scoped event subscription.
    pub async fn subscribe_events(
        &mut self,
        filter: EventFilter,
    ) -> Result<SubscriptionHandle, ClientError> {
        self.subscribe_events_with_deadline(filter, None).await
    }

    /// Opens an event subscription with an absolute Control API deadline.
    pub async fn subscribe_events_with_deadline(
        &mut self,
        filter: EventFilter,
        deadline_unix_ms: Option<i64>,
    ) -> Result<SubscriptionHandle, ClientError> {
        let request = api::SubscribeRequest {
            filter: Some(filter.to_proto()),
            resume_cursor: Vec::new(),
        };
        let response = self
            .request_with_deadline(
                "EventService",
                "Subscribe",
                request.encode_to_vec(),
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "EventService.Subscribe")?;
        let subscribed = api::SubscribeResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        subscribed
            .subscription_handle
            .as_ref()
            .map(|handle| SubscriptionHandle::from_proto_with_generation(handle, self.generation()))
            .ok_or_else(|| ClientError::Proto("subscribe response has no handle".into()))
    }

    /// Waits for the next event in a subscription. Events are delivered in
    /// per-subscription sequence order; a different subscription's event is
    /// retained by the daemon backend for its next call.
    pub async fn next_event(
        &mut self,
        subscription: &SubscriptionHandle,
    ) -> Result<Event, ClientError> {
        self.next_event_with_deadline(subscription, None).await
    }

    /// Waits for the next event with an absolute Control API deadline.
    pub async fn next_event_with_deadline(
        &mut self,
        subscription: &SubscriptionHandle,
        deadline_unix_ms: Option<i64>,
    ) -> Result<Event, ClientError> {
        subscription.validate_generation(self.generation())?;
        let wait = match deadline_unix_ms.filter(|deadline| *deadline > 0) {
            Some(deadline) => {
                let remaining = deadline.saturating_sub(now_unix_ms());
                if remaining <= 0 {
                    return Err(ClientError::DeadlineExceeded);
                }
                Some(Duration::from_millis(
                    u64::try_from(remaining).unwrap_or(u64::MAX),
                ))
            }
            None => None,
        };
        if self.is_embedded() {
            let Some(wait) = wait else {
                return self.recv_event(subscription.as_bytes()).await;
            };
            let started = tokio::time::Instant::now();
            loop {
                match self.recv_event(subscription.as_bytes()).await {
                    Err(ClientError::WouldBlock) => {
                        let elapsed = started.elapsed();
                        if elapsed >= wait {
                            return Err(ClientError::DeadlineExceeded);
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                    result => return result,
                }
            }
        }
        let next = self.recv_event(subscription.as_bytes());
        if let Some(wait) = wait {
            tokio::time::timeout(wait, next)
                .await
                .map_err(|_| ClientError::DeadlineExceeded)?
        } else {
            next.await
        }
    }

    /// Acknowledges the highest contiguous event sequence processed by the
    /// application. This controls local backlog retention only.
    pub async fn acknowledge_event(
        &mut self,
        subscription: &SubscriptionHandle,
        highest_contiguous_sequence: u64,
    ) -> Result<(), ClientError> {
        subscription.validate_generation(self.generation())?;
        self.acknowledge_event_raw(subscription.as_bytes(), highest_contiguous_sequence)
            .await
    }

    /// Closes an event subscription and releases its bounded backlog.
    pub async fn unsubscribe_events(
        &mut self,
        subscription: &SubscriptionHandle,
    ) -> Result<(), ClientError> {
        self.unsubscribe_events_with_deadline(subscription, None)
            .await
    }

    /// Closes an event subscription with an absolute Control API deadline.
    pub async fn unsubscribe_events_with_deadline(
        &mut self,
        subscription: &SubscriptionHandle,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        subscription.validate_generation(self.generation())?;
        let request = api::UnsubscribeRequest {
            subscription_handle: Some(subscription.to_proto()),
        };
        let response = self
            .request_with_deadline(
                "EventService",
                "Unsubscribe",
                request.encode_to_vec(),
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "EventService.Unsubscribe")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(payload_type: &str, payload: Vec<u8>) -> Event {
        Event::from_proto(
            api::Event {
                subscription_handle: Some(api::OpaqueHandle { value: vec![1] }),
                payload_type: payload_type.into(),
                payload,
                ..Default::default()
            },
            1,
        )
        .expect("event")
    }

    #[test]
    fn typed_delivery_and_path_events_preserve_handles_and_offsets() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&7u64.to_be_bytes());
        payload.extend_from_slice(&42u64.to_be_bytes());
        assert_eq!(
            event("stream_bytes_accepted", payload).delivery_event(),
            Some(DeliveryEvent::Acknowledged {
                stream_id: 7,
                offset: 42,
            })
        );
        assert_eq!(
            event("stream_reset", b"stream_id 9 error 55".to_vec()).delivery_event(),
            Some(DeliveryEvent::Reset {
                stream_id: 9,
                error_code: 55,
            })
        );
        assert_eq!(
            event("path_degraded", b"path 3: loss".to_vec()).path_event(),
            Some(PathEvent::Degraded { path_id: 3 })
        );
        assert_eq!(
            event("path_added", b"path 0 carrier embedded-loopback".to_vec()).path_event(),
            Some(PathEvent::Added {
                path_id: 0,
                carrier_type: "embedded-loopback".into(),
            })
        );
        assert_eq!(
            event("path_migrated", b"path 0 new_path 2".to_vec()).path_event(),
            Some(PathEvent::Migrated {
                old_path_id: 0,
                new_path_id: 2,
            })
        );
        assert_eq!(
            event("session_closed", b"peer reset".to_vec()).session_event(),
            Some(SessionEvent::Closed {
                reason: "peer reset".into()
            })
        );
    }
}
