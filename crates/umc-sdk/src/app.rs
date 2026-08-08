//! Typed application surface over the daemon backend (sdk.md §8–24, §27).
#![allow(clippy::missing_errors_doc)]
use std::collections::HashSet;

use prost::Message;
use umc_control::proto::umc::api::v1;

use crate::client::{Client, ClientError};
use crate::handles::{AppHandle, EndpointHandle, ListenerHandle, SessionHandle, StreamHandle};
use crate::policy::Policy;

/// Default daemon stream write chunk (sdk.md §27.1).
pub const SDK_CHUNK_SIZE: usize = 64 * 1024;
/// Maximum chunk accepted by the daemon backend (sdk.md §27.1).
pub const SDK_MAX_CHUNK_SIZE: usize = 256 * 1024;
/// Conservative default datagram bound before session negotiation is known.
pub const SDK_MAX_DATAGRAM_SIZE: usize = 256 * 1024;

/// Public endpoint metadata. Private keys and handshake secrets never appear
/// in this type.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    handle: EndpointHandle,
    endpoint_id: Vec<u8>,
    label: String,
    kind: i32,
    secret_available: bool,
}

impl Endpoint {
    /// Decodes endpoint metadata from the identity service response.
    pub fn from_summary(summary: &v1::IdentitySummary) -> Result<Self, ClientError> {
        let Some(handle) = summary.identity_handle.as_ref() else {
            return Err(ClientError::Proto("identity response has no handle".into()));
        };
        if summary.endpoint_id.is_empty() {
            return Err(ClientError::Proto(
                "identity response has no endpoint id".into(),
            ));
        }
        Ok(Self {
            handle: EndpointHandle::from_proto(handle),
            endpoint_id: summary.endpoint_id.clone(),
            label: summary.label.clone(),
            kind: summary.kind,
            secret_available: summary.secret_available,
        })
    }

    #[must_use]
    pub fn handle(&self) -> &EndpointHandle {
        &self.handle
    }

    #[must_use]
    pub fn endpoint_id(&self) -> &[u8] {
        &self.endpoint_id
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub const fn kind(&self) -> i32 {
        self.kind
    }

    /// Always false: the SDK intentionally exposes no private-key accessor.
    #[must_use]
    pub const fn exposes_private_key(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn secret_available(&self) -> bool {
        self.secret_available
    }
}

/// Listener metadata and its opaque daemon handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    handle: ListenerHandle,
    endpoint: EndpointHandle,
    protocol_id: String,
}

impl Listener {
    #[must_use]
    pub fn handle(&self) -> &ListenerHandle {
        &self.handle
    }

    #[must_use]
    pub fn endpoint(&self) -> &EndpointHandle {
        &self.endpoint
    }

    #[must_use]
    pub fn protocol_id(&self) -> &str {
        &self.protocol_id
    }
}

/// One complete datagram returned by the receive API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    session: SessionHandle,
    context_id: u64,
    data: Vec<u8>,
    expired: bool,
}

impl Datagram {
    #[must_use]
    pub fn session(&self) -> &SessionHandle {
        &self.session
    }

    #[must_use]
    pub const fn context_id(&self) -> u64 {
        self.context_id
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    #[must_use]
    pub const fn expired(&self) -> bool {
        self.expired
    }
}

/// Local protocol registry. Protocol IDs stay opaque to the daemon; this
/// registry only enforces the SDK's lowercase ASCII-compatible convention.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceRegistry {
    protocols: Vec<String>,
}

impl ServiceRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, protocol_id: &str) -> Result<(), ClientError> {
        validate_protocol_id(protocol_id)?;
        if self
            .protocols
            .iter()
            .any(|existing| existing == protocol_id)
        {
            return Err(ClientError::AlreadyExists);
        }
        self.protocols.push(protocol_id.to_string());
        Ok(())
    }

    pub fn unregister(&mut self, protocol_id: &str) -> Result<(), ClientError> {
        let Some(index) = self.protocols.iter().position(|id| id == protocol_id) else {
            return Err(ClientError::NotFound);
        };
        self.protocols.remove(index);
        Ok(())
    }

    #[must_use]
    pub fn contains(&self, protocol_id: &str) -> bool {
        self.protocols.iter().any(|id| id == protocol_id)
    }

    #[must_use]
    pub fn protocols(&self) -> &[String] {
        &self.protocols
    }
}

fn validate_protocol_id(protocol_id: &str) -> Result<(), ClientError> {
    if protocol_id.is_empty()
        || !protocol_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-._/".contains(&byte)
        })
    {
        return Err(ClientError::InvalidArgument);
    }
    Ok(())
}

fn encode<M: Message>(message: &M) -> Result<Vec<u8>, ClientError> {
    let mut payload = Vec::new();
    message
        .encode(&mut payload)
        .map_err(|error| ClientError::Proto(error.to_string()))?;
    Ok(payload)
}

fn require_ok(response: &v1::Response, method: &str) -> Result<(), ClientError> {
    let code = response
        .status
        .as_ref()
        .map_or(v1::StatusCode::Ok as i32, |status| status.code);
    if code == v1::StatusCode::Ok as i32 {
        Ok(())
    } else {
        Err(ClientError::from_status_for_method(code, method))
    }
}

impl Client {
    /// Creates a user endpoint without returning its private key.
    pub async fn create_endpoint(
        &mut self,
        label: &str,
        binding_lifetime_ms: u64,
    ) -> Result<Endpoint, ClientError> {
        let request = v1::CreateIdentityRequest {
            kind: v1::IdentityKind::UserEndpoint as i32,
            label: label.to_string(),
            binding_lifetime_ms: i64::try_from(binding_lifetime_ms).unwrap_or(i64::MAX),
        };
        let response = self
            .request("IdentityService", "CreateIdentity", encode(&request)?)
            .await?;
        require_ok(&response, "IdentityService.CreateIdentity")?;
        let created = v1::CreateIdentityResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        Endpoint::from_summary(
            created
                .identity
                .as_ref()
                .ok_or_else(|| ClientError::Proto("identity response has no summary".into()))?,
        )
    }

    /// Loads endpoint metadata by its daemon-side label.
    pub async fn load_endpoint(&mut self, label: &str) -> Result<Endpoint, ClientError> {
        let request = v1::ListIdentitiesRequest { page: None };
        let response = self
            .request("IdentityService", "ListIdentities", encode(&request)?)
            .await?;
        require_ok(&response, "IdentityService.ListIdentities")?;
        let listed = v1::ListIdentitiesResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        let summary = listed
            .identities
            .iter()
            .find(|identity| identity.label == label)
            .ok_or(ClientError::NotFound)?;
        Endpoint::from_summary(summary)
    }

    /// Imports an encrypted identity and returns only its public endpoint
    /// metadata. Secret material remains owned by the daemon backend.
    pub async fn import_endpoint(
        &mut self,
        encrypted_export: &[u8],
        passphrase: &[u8],
        os_key_reference: &str,
    ) -> Result<Endpoint, ClientError> {
        let request = v1::ImportIdentityRequest {
            encrypted_export: encrypted_export.to_vec(),
            passphrase: passphrase.to_vec(),
            os_key_reference: os_key_reference.to_string(),
            validate_only: false,
        };
        let response = self
            .request("IdentityService", "ImportIdentity", encode(&request)?)
            .await?;
        require_ok(&response, "IdentityService.ImportIdentity")?;
        let imported = v1::ImportIdentityResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        Endpoint::from_summary(
            imported
                .identity
                .as_ref()
                .ok_or_else(|| ClientError::Proto("import response has no summary".into()))?,
        )
    }

    /// Registers application protocols and returns an application-scoped
    /// handle. The daemon enforces capability grants and ownership.
    pub async fn register_application(
        &mut self,
        name: &str,
        instance_id: [u8; 16],
        endpoint_ids: &[&[u8]],
        protocols: &[&str],
    ) -> Result<AppHandle, ClientError> {
        if protocols.is_empty() {
            return Err(ClientError::InvalidArgument);
        }
        let mut validated = HashSet::with_capacity(protocols.len());
        for protocol in protocols {
            validate_protocol_id(protocol)?;
            if !validated.insert(*protocol) {
                return Err(ClientError::AlreadyExists);
            }
        }
        let request = v1::RegisterApplicationRequest {
            application_name: name.to_string(),
            application_instance_id: instance_id.to_vec(),
            requested_endpoint_ids: endpoint_ids.iter().map(|id| id.to_vec()).collect(),
            requested_protocol_ids: protocols.iter().map(|id| (*id).to_string()).collect(),
            requested_capabilities: Vec::new(),
            resumable: false,
        };
        let response = self
            .request(
                "ApplicationService",
                "RegisterApplication",
                encode(&request)?,
            )
            .await?;
        require_ok(&response, "ApplicationService.RegisterApplication")?;
        let registered = v1::RegisterApplicationResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        registered
            .application_handle
            .as_ref()
            .map(AppHandle::from_proto)
            .ok_or_else(|| ClientError::Proto("application response has no handle".into()))
    }

    /// Removes an application registration. This is idempotent only when the
    /// daemon still owns the handle; stale generations are rejected locally.
    pub async fn unregister_application(
        &mut self,
        application: &AppHandle,
        close_owned_sessions: bool,
    ) -> Result<(), ClientError> {
        let request = v1::UnregisterApplicationRequest {
            application_handle: Some(application.to_proto()),
            close_owned_sessions,
        };
        let response = self
            .request(
                "ApplicationService",
                "UnregisterApplication",
                encode(&request)?,
            )
            .await?;
        require_ok(&response, "ApplicationService.UnregisterApplication")
    }

    /// Binds a registered protocol to an endpoint.
    pub async fn listen(
        &mut self,
        application: &AppHandle,
        endpoint_id: &[u8],
        protocol_id: &str,
        policy: &Policy,
    ) -> Result<Listener, ClientError> {
        validate_protocol_id(protocol_id)?;
        let request = v1::OpenListenerRequest {
            application_handle: Some(application.to_proto()),
            endpoint_id: endpoint_id.to_vec(),
            protocol_id: protocol_id.to_string(),
            policy: Some(v1::ListenPolicy {
                minimum_trust: policy.minimum_trust as i32,
                allow_relay: policy.allow_relay,
                allow_early_data: false,
                maximum_pending_sessions: 256,
            }),
        };
        let response = self
            .request("ApplicationService", "OpenListener", encode(&request)?)
            .await?;
        require_ok(&response, "ApplicationService.OpenListener")?;
        let opened = v1::OpenListenerResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        let handle = opened
            .listener_handle
            .as_ref()
            .map(ListenerHandle::from_proto)
            .ok_or_else(|| ClientError::Proto("listener response has no handle".into()))?;
        Ok(Listener {
            handle,
            endpoint: EndpointHandle::new(endpoint_id.to_vec()),
            protocol_id: protocol_id.to_string(),
        })
    }

    /// Closes a listener without affecting accepted sessions.
    pub async fn close_listener(&mut self, listener: &Listener) -> Result<(), ClientError> {
        let request = v1::CloseListenerRequest {
            listener_handle: Some(listener.handle.to_proto()),
            close_owned_sessions: false,
        };
        let response = self
            .request("ApplicationService", "CloseListener", encode(&request)?)
            .await?;
        require_ok(&response, "ApplicationService.CloseListener")
    }

    /// Connects an application protocol to a destination hint or endpoint ID.
    pub async fn connect_session(
        &mut self,
        application: &AppHandle,
        destination_hint: &[u8],
        protocol_id: &str,
        policy: &Policy,
    ) -> Result<SessionHandle, ClientError> {
        self.connect_session_with_deadline(application, destination_hint, protocol_id, policy, None)
            .await
    }

    /// Connects with an absolute Control API deadline.
    pub async fn connect_session_with_deadline(
        &mut self,
        application: &AppHandle,
        destination_hint: &[u8],
        protocol_id: &str,
        policy: &Policy,
        deadline_unix_ms: Option<i64>,
    ) -> Result<SessionHandle, ClientError> {
        validate_protocol_id(protocol_id)?;
        let request = v1::ConnectRequest {
            application_handle: Some(application.to_proto()),
            destination_hint: destination_hint.to_vec(),
            protocol_id: protocol_id.to_string(),
            policy: Some(policy.to_connection_policy()),
            ..Default::default()
        };
        let response = self
            .request_with_deadline(
                "ApplicationService",
                "Connect",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "ApplicationService.Connect")?;
        let connected = v1::ConnectResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        connected
            .session_handle
            .as_ref()
            .map(SessionHandle::from_proto)
            .ok_or_else(|| ClientError::Proto("connect response has no session handle".into()))
    }

    /// Accepts a pending incoming session owned by the application.
    pub async fn accept_session(
        &mut self,
        application: &AppHandle,
        pending_session: &SessionHandle,
    ) -> Result<SessionHandle, ClientError> {
        let request = v1::AcceptIncomingSessionRequest {
            application_handle: Some(application.to_proto()),
            pending_session_handle: Some(pending_session.to_proto()),
        };
        let response = self
            .request(
                "ApplicationService",
                "AcceptIncomingSession",
                encode(&request)?,
            )
            .await?;
        require_ok(&response, "ApplicationService.AcceptIncomingSession")?;
        let accepted = v1::AcceptIncomingSessionResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        accepted
            .session_handle
            .as_ref()
            .map(SessionHandle::from_proto)
            .ok_or_else(|| ClientError::Proto("accept response has no session handle".into()))
    }

    /// Opens one bidirectional or unidirectional stream.
    pub async fn open_stream(
        &mut self,
        application: &AppHandle,
        session: &SessionHandle,
        unidirectional: bool,
    ) -> Result<StreamHandle, ClientError> {
        let request = v1::OpenStreamRequest {
            application_handle: Some(application.to_proto()),
            session_handle: Some(session.to_proto()),
            unidirectional,
            initial_metadata: Vec::new(),
        };
        let response = self
            .request("ApplicationService", "OpenStream", encode(&request)?)
            .await?;
        require_ok(&response, "ApplicationService.OpenStream")?;
        let opened = v1::OpenStreamResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        opened
            .stream_handle
            .as_ref()
            .map(StreamHandle::from_proto)
            .ok_or_else(|| ClientError::Proto("stream response has no handle".into()))
    }

    /// Writes bounded chunks and returns the number of bytes accepted by the
    /// daemon. A successful return means local ownership only.
    pub async fn write_stream(
        &mut self,
        stream: &StreamHandle,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, ClientError> {
        let mut accepted = 0usize;
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![data]
        } else {
            data.chunks(SDK_CHUNK_SIZE).collect()
        };
        for (index, chunk) in chunks.iter().enumerate() {
            let request = v1::WriteStreamRequest {
                stream_handle: Some(stream.to_proto()),
                data: (*chunk).to_vec(),
                fin: fin && index + 1 == chunks.len(),
            };
            let response = self
                .request("ApplicationService", "WriteStream", encode(&request)?)
                .await?;
            require_ok(&response, "ApplicationService.WriteStream")?;
            let written = v1::WriteStreamResponse::decode(response.payload.as_slice())
                .map_err(|error| ClientError::Proto(error.to_string()))?;
            accepted = accepted.saturating_add(written.accepted_bytes as usize);
        }
        Ok(accepted)
    }

    /// Reads at most the requested number of bytes, bounded by the SDK's
    /// maximum chunk size.
    pub async fn read_stream(
        &mut self,
        stream: &StreamHandle,
        maximum_bytes: usize,
        wait_for_data: bool,
    ) -> Result<(Vec<u8>, bool), ClientError> {
        let maximum_bytes = maximum_bytes.min(SDK_MAX_CHUNK_SIZE);
        let request = v1::ReadStreamRequest {
            stream_handle: Some(stream.to_proto()),
            maximum_bytes: u32::try_from(maximum_bytes).unwrap_or(u32::MAX),
            wait_for_data,
        };
        let response = self
            .request("ApplicationService", "ReadStream", encode(&request)?)
            .await?;
        require_ok(&response, "ApplicationService.ReadStream")?;
        let read = v1::ReadStreamResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        if read.reset {
            return Err(ClientError::StreamReset {
                stream_id: 0,
                error_code: read.application_error_code,
            });
        }
        Ok((read.data, read.eof))
    }

    /// Sends a FIN on a stream.
    pub async fn close_stream_send(&mut self, stream: &StreamHandle) -> Result<(), ClientError> {
        self.stream_control(
            "CloseStreamSend",
            v1::CloseStreamSendRequest {
                stream_handle: Some(stream.to_proto()),
            }
            .encode_to_vec(),
            "ApplicationService.CloseStreamSend",
        )
        .await
    }

    /// Resets one stream direction.
    pub async fn reset_stream(
        &mut self,
        stream: &StreamHandle,
        error_code: u64,
    ) -> Result<(), ClientError> {
        self.stream_control(
            "ResetStream",
            v1::ResetStreamRequest {
                stream_handle: Some(stream.to_proto()),
                application_error_code: error_code,
            }
            .encode_to_vec(),
            "ApplicationService.ResetStream",
        )
        .await
    }

    /// Requests that the peer stop sending on one stream.
    pub async fn stop_stream(
        &mut self,
        stream: &StreamHandle,
        error_code: u64,
    ) -> Result<(), ClientError> {
        self.stream_control(
            "StopStream",
            v1::StopStreamRequest {
                stream_handle: Some(stream.to_proto()),
                application_error_code: error_code,
            }
            .encode_to_vec(),
            "ApplicationService.StopStream",
        )
        .await
    }

    async fn stream_control(
        &mut self,
        method: &str,
        payload: Vec<u8>,
        label: &str,
    ) -> Result<(), ClientError> {
        let response = self.request("ApplicationService", method, payload).await?;
        require_ok(&response, label)
    }

    /// Accepts one complete datagram locally; delivery is not implied.
    pub async fn send_datagram(
        &mut self,
        session: &SessionHandle,
        context_id: u64,
        data: &[u8],
        lifetime_ms: u64,
        request_ack: bool,
    ) -> Result<u64, ClientError> {
        if data.len() > SDK_MAX_DATAGRAM_SIZE {
            return Err(ClientError::InvalidArgument);
        }
        let request = v1::SendDatagramRequest {
            session_handle: Some(session.to_proto()),
            context_id,
            data: data.to_vec(),
            lifetime_ms,
            request_ack,
        };
        let response = self
            .request("ApplicationService", "SendDatagram", encode(&request)?)
            .await?;
        require_ok(&response, "ApplicationService.SendDatagram")?;
        let sent = v1::SendDatagramResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        Ok(sent.local_datagram_id)
    }

    /// Receives one complete datagram without truncation.
    pub async fn receive_datagram(
        &mut self,
        application: &AppHandle,
        session: &SessionHandle,
        maximum_bytes: usize,
        wait_for_data: bool,
    ) -> Result<Datagram, ClientError> {
        let request = v1::ReceiveDatagramRequest {
            application_handle: Some(application.to_proto()),
            session_handle: Some(session.to_proto()),
            maximum_bytes: u32::try_from(maximum_bytes.min(SDK_MAX_DATAGRAM_SIZE))
                .unwrap_or(u32::MAX),
            wait_for_data,
        };
        let response = self
            .request("ApplicationService", "ReceiveDatagram", encode(&request)?)
            .await?;
        require_ok(&response, "ApplicationService.ReceiveDatagram")?;
        let received = v1::ReceiveDatagramResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        let received_session = received
            .session_handle
            .as_ref()
            .map(SessionHandle::from_proto)
            .ok_or_else(|| ClientError::Proto("datagram response has no session".into()))?;
        if received.data.len() > maximum_bytes {
            return Err(ClientError::InvalidArgument);
        }
        Ok(Datagram {
            session: received_session,
            context_id: received.context_id,
            data: received.data,
            expired: received.expired,
        })
    }
}
