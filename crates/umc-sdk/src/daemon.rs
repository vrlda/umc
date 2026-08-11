//! Low-level daemon connection (sdk.md §27): socket handshake plus raw
//! requests returning `(status_code, payload)`. Typed clients in
//! [`crate::client`], [`crate::config`], and [`crate::status`] build on
//! this.
use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use umc_control::framing::{frame_envelope, EnvelopeDecoder};
use umc_control::proto::umc::api::v1 as api;

use crate::client::ClientError;
use crate::events::Event;

const MAX_PENDING_RESPONSES: usize = 1_024;
const MAX_PENDING_EVENTS: usize = 100;
const MAX_PENDING_ENVELOPES: usize = 1_024;

/// Connected daemon control socket with hello negotiation done.
#[derive(Debug)]
pub struct DaemonClient {
    stream: UnixStream,
    sequence: u64,
    request_id: u64,
    generation: u64,
    envelope_max: usize,
    decoder: EnvelopeDecoder,
    pending_envelopes: VecDeque<api::Envelope>,
    pending_responses: VecDeque<api::Response>,
    pending_events: VecDeque<api::Event>,
}

impl DaemonClient {
    /// Connects to the daemon's control socket and negotiates the API version.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Io`] when the socket cannot be connected, and
    /// [`ClientError::VersionMismatch`] or [`ClientError::Denied`] when the
    /// handshake is not accepted.
    pub async fn connect(socket: &str, client_name: &str) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(socket)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        let mut client = Self {
            stream,
            sequence: 1,
            request_id: 0,
            generation: 0,
            envelope_max: 4 * 1024 * 1024,
            decoder: EnvelopeDecoder::new(4 * 1024 * 1024),
            pending_envelopes: VecDeque::new(),
            pending_responses: VecDeque::new(),
            pending_events: VecDeque::new(),
        };
        client.hello(client_name).await?;
        Ok(client)
    }

    /// Sends a request and returns the raw `(status_code, response_payload)`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Denied`] when the reply is not a Response
    /// envelope, and [`ClientError::Io`], [`ClientError::Framing`], or
    /// [`ClientError::Proto`] for transport and decode failures. Non-OK
    /// status codes are returned to the caller, not converted to errors.
    pub async fn request_raw(
        &mut self,
        service: &str,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<(i32, Vec<u8>), ClientError> {
        self.request_raw_with_deadline(service, method, payload, None)
            .await
    }

    /// Sends a request with an absolute wall-clock deadline in the Control
    /// API envelope. Both client and daemon reject expired work instead of
    /// allowing an unbounded operation to occupy the connection.
    ///
    /// # Errors
    ///
    /// Returns transport, framing, or protocol decoding errors.
    pub async fn request_raw_with_deadline(
        &mut self,
        service: &str,
        method: &str,
        payload: Vec<u8>,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(i32, Vec<u8>), ClientError> {
        let timeout = request_timeout(deadline_unix_ms)?;
        self.request_id += 1;
        let request_id = self.request_id;
        let request = request_envelope_with_deadline(
            self.next_sequence(),
            request_id,
            service,
            method,
            payload,
            deadline_unix_ms,
        );
        self.send(&request).await?;
        let response = match timeout {
            Some(duration) => {
                if let Ok(response) =
                    tokio::time::timeout(duration, self.recv_response(request_id)).await
                {
                    response?
                } else {
                    let cancel =
                        cancel_envelope(self.next_sequence(), request_id, "deadline exceeded");
                    let _ = self.send(&cancel).await;
                    return Err(ClientError::DeadlineExceeded);
                }
            }
            None => self.recv_response(request_id).await?,
        };
        let code = response.status.as_ref().map_or(0, |s| s.code);
        Ok((code, response.payload))
    }

    async fn recv_response(&mut self, request_id: u64) -> Result<api::Response, ClientError> {
        if let Some(index) = self
            .pending_responses
            .iter()
            .position(|response| response.request_id == request_id)
        {
            return self
                .pending_responses
                .remove(index)
                .ok_or(ClientError::Denied);
        }
        loop {
            let envelope = self.recv_envelope().await?;
            match envelope.body {
                Some(api::envelope::Body::Response(response))
                    if response.request_id == request_id =>
                {
                    return Ok(response)
                }
                Some(api::envelope::Body::Response(response)) => {
                    push_bounded(&mut self.pending_responses, response, MAX_PENDING_RESPONSES)?;
                }
                Some(api::envelope::Body::Event(event)) => {
                    push_bounded(&mut self.pending_events, event, MAX_PENDING_EVENTS)?;
                }
                Some(api::envelope::Body::GoAway(_)) => return Err(ClientError::Unavailable),
                _ => return Err(ClientError::Denied),
            }
        }
    }

    /// Waits for the next event belonging to a subscription. Responses that
    /// arrive while waiting are retained for the next request, and events for
    /// other subscriptions remain queued in arrival order.
    pub(crate) async fn recv_event(&mut self, subscription: &[u8]) -> Result<Event, ClientError> {
        if let Some(index) = self.pending_events.iter().position(|event| {
            event
                .subscription_handle
                .as_ref()
                .is_some_and(|handle| handle.value == subscription)
        }) {
            let event = self
                .pending_events
                .remove(index)
                .ok_or(ClientError::Denied)?;
            return Event::from_proto(event, self.generation);
        }
        loop {
            let envelope = self.recv_envelope().await?;
            match envelope.body {
                Some(api::envelope::Body::Event(event)) => {
                    let is_requested = event
                        .subscription_handle
                        .as_ref()
                        .is_some_and(|handle| handle.value == subscription);
                    if is_requested {
                        return Event::from_proto(event, self.generation);
                    }
                    push_bounded(&mut self.pending_events, event, MAX_PENDING_EVENTS)?;
                }
                Some(api::envelope::Body::Response(response)) => {
                    self.pending_responses.push_back(response);
                }
                Some(api::envelope::Body::GoAway(_)) => return Err(ClientError::Unavailable),
                _ => return Err(ClientError::Denied),
            }
        }
    }

    /// Sends a flow-control acknowledgement for a subscription. The control
    /// protocol deliberately has no response envelope for `EventAck`.
    pub(crate) async fn acknowledge_event(
        &mut self,
        subscription: &[u8],
        highest_contiguous_sequence: u64,
    ) -> Result<(), ClientError> {
        let envelope = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: self.next_sequence(),
            body: Some(api::envelope::Body::EventAck(api::EventAck {
                subscription_handle: Some(api::OpaqueHandle {
                    value: subscription.to_vec(),
                }),
                highest_contiguous_sequence,
            })),
        };
        self.send(&envelope).await
    }

    /// Generation shared by handles decoded from this daemon connection.
    /// It changes when either the daemon instance or the control connection
    /// changes, so stale handles fail local validation before a request is
    /// sent.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    async fn hello(&mut self, client_name: &str) -> Result<(), ClientError> {
        let hello = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: self.next_sequence(),
            body: Some(api::envelope::Body::ClientHello(api::ClientHello {
                supported_versions: vec![api::ApiVersion { major: 1, minor: 0 }],
                client_name: client_name.to_string(),
                ..Default::default()
            })),
        };
        self.send(&hello).await?;
        let reply = self.recv_envelope().await?;
        match reply.body {
            Some(api::envelope::Body::ServerHello(sh)) => {
                let version = sh.selected_version.ok_or(ClientError::VersionMismatch)?;
                if version.major != 1 {
                    return Err(ClientError::VersionMismatch);
                }
                self.envelope_max = usize::try_from(sh.negotiated_envelope_size.max(1024))
                    .unwrap_or(4 * 1024 * 1024);
                self.generation = backend_generation(&sh.server_instance_id, &sh.connection_id);
                Ok(())
            }
            _ => Err(ClientError::Denied),
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence;
        self.sequence += 1;
        seq
    }

    async fn send(&mut self, envelope: &api::Envelope) -> Result<(), ClientError> {
        let mut bytes = Vec::new();
        Message::encode(envelope, &mut bytes).map_err(|e| ClientError::Proto(e.to_string()))?;
        let mut framed = Vec::new();
        frame_envelope(&mut framed, &bytes, self.envelope_max).map_err(ClientError::Framing)?;
        self.stream
            .write_all(&framed)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))
    }

    pub(crate) async fn recv_envelope(&mut self) -> Result<api::Envelope, ClientError> {
        if let Some(envelope) = self.pending_envelopes.pop_front() {
            return Ok(envelope);
        }
        let mut buf = [0u8; 8 * 1024];
        loop {
            let n = self
                .stream
                .read(&mut buf)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
            if n == 0 {
                return Err(ClientError::Io("connection closed".into()));
            }
            let envelopes = self.decoder.feed(&buf[..n]).map_err(ClientError::Framing)?;
            let decoded = envelopes
                .into_iter()
                .map(|envelope| {
                    api::Envelope::decode(envelope.as_slice())
                        .map_err(|e| ClientError::Proto(e.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if self.pending_envelopes.len() + decoded.len() > MAX_PENDING_ENVELOPES {
                return Err(ClientError::ResourceExhausted);
            }
            self.pending_envelopes.extend(decoded);
            if let Some(envelope) = self.pending_envelopes.pop_front() {
                return Ok(envelope);
            }
        }
    }
}

fn push_bounded<T>(queue: &mut VecDeque<T>, value: T, capacity: usize) -> Result<(), ClientError> {
    if queue.len() >= capacity {
        return Err(ClientError::ResourceExhausted);
    }
    queue.push_back(value);
    Ok(())
}

fn request_timeout(deadline_unix_ms: Option<i64>) -> Result<Option<Duration>, ClientError> {
    let Some(deadline) = deadline_unix_ms else {
        return Ok(None);
    };
    if deadline < 0 {
        return Err(ClientError::InvalidArgument);
    }
    if deadline == 0 {
        return Ok(None);
    }
    let remaining = deadline.saturating_sub(now_unix_ms());
    if remaining <= 0 {
        return Err(ClientError::DeadlineExceeded);
    }
    Ok(Some(Duration::from_millis(
        u64::try_from(remaining).unwrap_or(u64::MAX),
    )))
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

fn backend_generation(server_instance_id: &[u8], connection_id: &[u8]) -> u64 {
    // A generation is an opaque local validation value, not an authenticator.
    // FNV-1a keeps it deterministic across clients while mixing both the
    // daemon boot identity and this control connection's identity.
    let mut value = 0xcbf2_9ce4_8422_2325u64;
    for byte in server_instance_id.iter().chain(connection_id) {
        value ^= u64::from(*byte);
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if value == 0 {
        1
    } else {
        value
    }
}

fn request_envelope_with_deadline(
    sequence: u64,
    request_id: u64,
    service: &str,
    method: &str,
    payload: Vec<u8>,
    deadline_unix_ms: Option<i64>,
) -> api::Envelope {
    api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence,
        body: Some(api::envelope::Body::Request(api::Request {
            request_id,
            service: service.to_string(),
            method: method.to_string(),
            deadline_unix_ms: deadline_unix_ms.unwrap_or_default(),
            payload,
            ..Default::default()
        })),
    }
}

fn cancel_envelope(sequence: u64, request_id: u64, reason: &str) -> api::Envelope {
    api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence,
        body: Some(api::envelope::Body::Cancel(api::Cancel {
            request_id,
            reason: reason.to_string(),
        })),
    }
}

/// Encodes a request envelope to bytes. Exposed for unit tests that pin the
/// wire shape without a live daemon.
///
/// # Errors
///
/// Returns [`ClientError::Proto`] when encoding fails.
#[cfg(test)]
pub(crate) fn encode_request(
    sequence: u64,
    request_id: u64,
    service: &str,
    method: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    encode_request_with_deadline(sequence, request_id, service, method, payload, None)
}

/// Encodes a request with a deadline for SDK request-shape tests and backend
/// adapters.
#[cfg(test)]
pub(crate) fn encode_request_with_deadline(
    sequence: u64,
    request_id: u64,
    service: &str,
    method: &str,
    payload: Vec<u8>,
    deadline_unix_ms: Option<i64>,
) -> Result<Vec<u8>, ClientError> {
    let mut bytes = Vec::new();
    Message::encode(
        &request_envelope_with_deadline(
            sequence,
            request_id,
            service,
            method,
            payload,
            deadline_unix_ms,
        ),
        &mut bytes,
    )
    .map_err(|e| ClientError::Proto(e.to_string()))?;
    Ok(bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn backend_generation_changes_with_instance_or_connection() {
        let first = backend_generation(&[1; 16], &[2; 16]);
        assert_ne!(first, 0);
        assert_ne!(first, backend_generation(&[3; 16], &[2; 16]));
        assert_ne!(first, backend_generation(&[1; 16], &[4; 16]));
    }

    #[test]
    fn request_timeout_rejects_invalid_and_expired_deadlines() {
        assert_eq!(request_timeout(None).expect("no deadline"), None);
        assert_eq!(request_timeout(Some(0)).expect("default deadline"), None);
        assert_eq!(
            request_timeout(Some(-1)).expect_err("negative deadline"),
            ClientError::InvalidArgument
        );
        assert_eq!(
            request_timeout(Some(now_unix_ms().saturating_sub(1))).expect_err("expired deadline"),
            ClientError::DeadlineExceeded
        );
        assert!(request_timeout(Some(i64::MAX))
            .expect("future deadline")
            .is_some());
    }

    #[test]
    fn cancel_envelope_binds_request_id_and_reason() {
        let envelope = cancel_envelope(9, 42, "deadline exceeded");
        assert_eq!(envelope.sequence, 9);
        match envelope.body {
            Some(api::envelope::Body::Cancel(cancel)) => {
                assert_eq!(cancel.request_id, 42);
                assert_eq!(cancel.reason, "deadline exceeded");
            }
            other => panic!("expected Cancel envelope, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deadline_timeout_notifies_daemon_with_cancel() {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("socket pair");
        let server = tokio::spawn(async move {
            let mut decoder = EnvelopeDecoder::new(4 * 1024 * 1024);
            let mut buf = [0u8; 1024];
            let mut bodies = Vec::new();
            while bodies.len() < 2 {
                let n = server_stream.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                for encoded in decoder.feed(&buf[..n]).expect("frame") {
                    bodies.push(api::Envelope::decode(encoded.as_slice()).expect("decode"));
                }
            }
            bodies
        });
        let mut client = DaemonClient {
            stream: client_stream,
            sequence: 1,
            request_id: 0,
            generation: 0,
            envelope_max: 4 * 1024 * 1024,
            decoder: EnvelopeDecoder::new(4 * 1024 * 1024),
            pending_envelopes: VecDeque::new(),
            pending_responses: VecDeque::new(),
            pending_events: VecDeque::new(),
        };
        let deadline = now_unix_ms().saturating_add(20);
        assert_eq!(
            client
                .request_raw_with_deadline("NodeAdmin", "GetStatus", Vec::new(), Some(deadline))
                .await
                .expect_err("request must time out"),
            ClientError::DeadlineExceeded
        );
        let bodies = tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("cancel reaches daemon")
            .expect("server task");
        assert!(matches!(
            bodies.first().and_then(|envelope| envelope.body.as_ref()),
            Some(api::envelope::Body::Request(request)) if request.request_id == 1
        ));
        assert!(matches!(
            bodies.get(1).and_then(|envelope| envelope.body.as_ref()),
            Some(api::envelope::Body::Cancel(cancel))
                if cancel.request_id == 1 && cancel.reason == "deadline exceeded"
        ));
    }

    #[test]
    fn pending_envelope_queues_are_bounded() {
        let mut queue = VecDeque::new();
        for value in 0..MAX_PENDING_RESPONSES {
            push_bounded(&mut queue, value, MAX_PENDING_RESPONSES).expect("within cap");
        }
        assert_eq!(
            push_bounded(&mut queue, 99, MAX_PENDING_RESPONSES),
            Err(ClientError::ResourceExhausted)
        );
    }

    #[tokio::test]
    async fn recv_preserves_coalesced_envelopes() {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("socket pair");
        let first = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: 1,
            body: Some(api::envelope::Body::GoAway(api::GoAway::default())),
        };
        let second = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: 2,
            body: Some(api::envelope::Body::GoAway(api::GoAway::default())),
        };
        let mut framed = Vec::new();
        for envelope in [&first, &second] {
            let mut encoded = Vec::new();
            Message::encode(envelope, &mut encoded).expect("encode");
            frame_envelope(&mut framed, &encoded, 4 * 1024 * 1024).expect("frame");
        }
        server_stream.write_all(&framed).await.expect("write");
        drop(server_stream);

        let mut client = DaemonClient {
            stream: client_stream,
            sequence: 3,
            request_id: 0,
            generation: 0,
            envelope_max: 4 * 1024 * 1024,
            decoder: EnvelopeDecoder::new(4 * 1024 * 1024),
            pending_envelopes: VecDeque::new(),
            pending_responses: VecDeque::new(),
            pending_events: VecDeque::new(),
        };
        assert_eq!(client.recv_envelope().await.expect("first").sequence, 1);
        assert_eq!(client.recv_envelope().await.expect("second").sequence, 2);
    }

    #[tokio::test]
    async fn request_and_event_envelopes_can_arrive_interleaved() {
        let (client_stream, mut server_stream) = UnixStream::pair().expect("socket pair");
        let response = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: 1,
            body: Some(api::envelope::Body::Response(api::Response {
                request_id: 1,
                status: Some(api::Status {
                    code: api::StatusCode::Ok as i32,
                    ..Default::default()
                }),
                payload: b"response".to_vec(),
                ..Default::default()
            })),
        };
        let event = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: 2,
            body: Some(api::envelope::Body::Event(api::Event {
                subscription_handle: Some(api::OpaqueHandle {
                    value: b"subscription".to_vec(),
                }),
                event_sequence: 1,
                event_type: api::EventType::NodeState as i32,
                event_class: api::EventClass::State as i32,
                ..Default::default()
            })),
        };
        let mut framed = Vec::new();
        for envelope in [&response, &event] {
            let mut encoded = Vec::new();
            Message::encode(envelope, &mut encoded).expect("encode");
            frame_envelope(&mut framed, &encoded, 4 * 1024 * 1024).expect("frame");
        }
        let server = tokio::spawn(async move {
            let mut request_bytes = [0u8; 256];
            let _ = server_stream.read(&mut request_bytes).await;
            server_stream.write_all(&framed).await.expect("write");
        });

        let mut client = DaemonClient {
            stream: client_stream,
            sequence: 1,
            request_id: 0,
            generation: 9,
            envelope_max: 4 * 1024 * 1024,
            decoder: EnvelopeDecoder::new(4 * 1024 * 1024),
            pending_envelopes: VecDeque::new(),
            pending_responses: VecDeque::new(),
            pending_events: VecDeque::new(),
        };
        let (code, payload) = client
            .request_raw("NodeAdmin", "GetStatus", Vec::new())
            .await
            .expect("response");
        assert_eq!(code, api::StatusCode::Ok as i32);
        assert_eq!(payload, b"response");
        let event = client
            .recv_event(b"subscription")
            .await
            .expect("queued event");
        assert_eq!(event.sequence(), 1);
        assert_eq!(event.subscription().as_bytes(), b"subscription");
        server.await.expect("server task");
    }
}
