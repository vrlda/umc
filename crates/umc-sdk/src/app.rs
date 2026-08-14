//! Typed application surface over the daemon backend (sdk.md §8–24, §27).
#![allow(clippy::missing_errors_doc)]
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use umc_control::proto::umc::api::v1;

use crate::client::{Client, ClientError};
use crate::handles::{
    AppHandle, EndpointHandle, GenerationBound, ListenerHandle, SessionHandle, StreamHandle,
};
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

/// Public material returned when a root endpoint provisions another device.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    certificate: Vec<u8>,
    delegation_chain: Vec<u8>,
    root_public_key: Vec<u8>,
}

impl Delegation {
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
    #[must_use]
    pub fn delegation_chain(&self) -> &[u8] {
        &self.delegation_chain
    }
    #[must_use]
    pub fn root_public_key(&self) -> &[u8] {
        &self.root_public_key
    }
}

/// Public summary of one persisted delegated leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationSummary {
    pub root_public_key: Vec<u8>,
    pub delegated_public_key: Vec<u8>,
    pub depth: u32,
    pub sequence: u64,
    pub expires_at_unix_ms: u64,
    pub capabilities: Vec<Vec<u8>>,
}

/// Result of an application registration. The daemon may narrow requested
/// capabilities to the authenticated principal's effective grants and may
/// issue a resumable registration token.
#[derive(Debug, Clone, PartialEq)]
pub struct ApplicationRegistration {
    handle: AppHandle,
    effective_grants: Vec<v1::CapabilityGrant>,
    resume_token: Vec<u8>,
}

impl ApplicationRegistration {
    #[must_use]
    pub fn handle(&self) -> &AppHandle {
        &self.handle
    }

    #[must_use]
    pub fn effective_grants(&self) -> &[v1::CapabilityGrant] {
        &self.effective_grants
    }

    #[must_use]
    pub fn resume_token(&self) -> &[u8] {
        &self.resume_token
    }
}

impl Endpoint {
    /// Decodes endpoint metadata from the identity service response.
    pub fn from_summary(summary: &v1::IdentitySummary) -> Result<Self, ClientError> {
        Self::from_summary_with_generation(summary, 0)
    }

    pub(crate) fn from_summary_with_generation(
        summary: &v1::IdentitySummary,
        generation: u64,
    ) -> Result<Self, ClientError> {
        let Some(handle) = summary.identity_handle.as_ref() else {
            return Err(ClientError::Proto("identity response has no handle".into()));
        };
        if summary.endpoint_id.is_empty() {
            return Err(ClientError::Proto(
                "identity response has no endpoint id".into(),
            ));
        }
        Ok(Self {
            handle: EndpointHandle::from_proto_with_generation(handle, generation),
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
    fn validate_handle<H: GenerationBound>(&self, handle: &H) -> Result<(), ClientError> {
        handle.validate_backend_generation(self.generation())
    }

    /// Creates a user endpoint without returning its private key.
    pub async fn create_endpoint(
        &mut self,
        label: &str,
        binding_lifetime_ms: u64,
    ) -> Result<Endpoint, ClientError> {
        self.create_endpoint_with_deadline(label, binding_lifetime_ms, None)
            .await
    }

    /// Creates a user endpoint with an absolute Control API deadline.
    pub async fn create_endpoint_with_deadline(
        &mut self,
        label: &str,
        binding_lifetime_ms: u64,
        deadline_unix_ms: Option<i64>,
    ) -> Result<Endpoint, ClientError> {
        let request = v1::CreateIdentityRequest {
            kind: v1::IdentityKind::UserEndpoint as i32,
            label: label.to_string(),
            binding_lifetime_ms: i64::try_from(binding_lifetime_ms).unwrap_or(i64::MAX),
        };
        let response = self
            .request_with_deadline(
                "IdentityService",
                "CreateIdentity",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "IdentityService.CreateIdentity")?;
        let created = v1::CreateIdentityResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        Endpoint::from_summary_with_generation(
            created
                .identity
                .as_ref()
                .ok_or_else(|| ClientError::Proto("identity response has no summary".into()))?,
            self.generation(),
        )
    }

    /// Loads endpoint metadata by its daemon-side label.
    pub async fn load_endpoint(&mut self, label: &str) -> Result<Endpoint, ClientError> {
        self.load_endpoint_with_deadline(label, None).await
    }

    /// Loads endpoint metadata with an absolute Control API deadline.
    pub async fn load_endpoint_with_deadline(
        &mut self,
        label: &str,
        deadline_unix_ms: Option<i64>,
    ) -> Result<Endpoint, ClientError> {
        let request = v1::ListIdentitiesRequest { page: None };
        let response = self
            .request_with_deadline(
                "IdentityService",
                "ListIdentities",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "IdentityService.ListIdentities")?;
        let listed = v1::ListIdentitiesResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        let summary = listed
            .identities
            .iter()
            .find(|identity| identity.label == label)
            .ok_or(ClientError::NotFound)?;
        Endpoint::from_summary_with_generation(summary, self.generation())
    }

    /// Imports an encrypted identity and returns only its public endpoint
    /// metadata. Secret material remains owned by the daemon backend.
    pub async fn import_endpoint(
        &mut self,
        encrypted_export: &[u8],
        passphrase: &[u8],
        os_key_reference: &str,
    ) -> Result<Endpoint, ClientError> {
        self.import_endpoint_with_deadline(encrypted_export, passphrase, os_key_reference, None)
            .await
    }

    /// Imports an encrypted identity with an absolute Control API deadline.
    pub async fn import_endpoint_with_deadline(
        &mut self,
        encrypted_export: &[u8],
        passphrase: &[u8],
        os_key_reference: &str,
        deadline_unix_ms: Option<i64>,
    ) -> Result<Endpoint, ClientError> {
        let request = v1::ImportIdentityRequest {
            encrypted_export: encrypted_export.to_vec(),
            passphrase: passphrase.to_vec(),
            os_key_reference: os_key_reference.to_string(),
            validate_only: false,
        };
        let response = self
            .request_with_deadline(
                "IdentityService",
                "ImportIdentity",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "IdentityService.ImportIdentity")?;
        let imported = v1::ImportIdentityResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        Endpoint::from_summary_with_generation(
            imported
                .identity
                .as_ref()
                .ok_or_else(|| ClientError::Proto("import response has no summary".into()))?,
            self.generation(),
        )
    }

    /// Creates and persists a bounded signed delegation for a device key.
    pub async fn create_delegation(
        &mut self,
        identity: &EndpointHandle,
        delegated_public_key: [u8; 32],
        allowed_capabilities: &[Vec<u8>],
        root_capabilities: &[Vec<u8>],
        expires_at_unix_ms: i64,
        deadline_unix_ms: Option<i64>,
    ) -> Result<Delegation, ClientError> {
        self.validate_handle(identity)?;
        let request = v1::CreateDelegationRequest {
            identity_handle: Some(identity.to_proto()),
            delegated_public_key: delegated_public_key.to_vec(),
            allowed_capabilities: allowed_capabilities.to_vec(),
            expires_at_unix_ms,
            root_capabilities: root_capabilities.to_vec(),
        };
        let response = self
            .request_with_deadline(
                "IdentityService",
                "CreateDelegation",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "IdentityService.CreateDelegation")?;
        let created = v1::CreateDelegationResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        Ok(Delegation {
            certificate: created.certificate,
            delegation_chain: created.delegation_chain,
            root_public_key: created.root_public_key,
        })
    }

    /// Imports a public delegation chain into the local trust store.
    pub async fn import_delegation(
        &mut self,
        root_public_key: [u8; 32],
        root_capabilities: &[Vec<u8>],
        delegation_chain: &[u8],
        deadline_unix_ms: Option<i64>,
    ) -> Result<Vec<u8>, ClientError> {
        let request = v1::ImportDelegationRequest {
            root_public_key: root_public_key.to_vec(),
            root_capabilities: root_capabilities.to_vec(),
            delegation_chain: delegation_chain.to_vec(),
        };
        let response = self
            .request_with_deadline(
                "IdentityService",
                "ImportDelegation",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "IdentityService.ImportDelegation")?;
        Ok(
            v1::ImportDelegationResponse::decode(response.payload.as_slice())
                .map_err(|error| ClientError::Proto(error.to_string()))?
                .delegated_public_key,
        )
    }

    /// Lists only public metadata for locally persisted delegated devices.
    pub async fn list_delegations(
        &mut self,
        deadline_unix_ms: Option<i64>,
    ) -> Result<Vec<DelegationSummary>, ClientError> {
        let response = self
            .request_with_deadline(
                "IdentityService",
                "ListDelegations",
                encode(&v1::ListDelegationsRequest {})?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "IdentityService.ListDelegations")?;
        Ok(
            v1::ListDelegationsResponse::decode(response.payload.as_slice())
                .map_err(|error| ClientError::Proto(error.to_string()))?
                .delegations
                .into_iter()
                .map(|summary| DelegationSummary {
                    root_public_key: summary.root_public_key,
                    delegated_public_key: summary.delegated_public_key,
                    depth: summary.depth,
                    sequence: summary.sequence,
                    expires_at_unix_ms: summary.expires_at_unix_ms,
                    capabilities: summary.capabilities,
                })
                .collect(),
        )
    }

    /// Revokes a delegated leaf using the selected root endpoint.
    pub async fn revoke_delegation(
        &mut self,
        identity: &EndpointHandle,
        delegated_public_key: [u8; 32],
        sequence: u64,
        expires_at_unix_ms: i64,
        reason: &str,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        self.validate_handle(identity)?;
        let request = v1::RevokeDelegationRequest {
            identity_handle: Some(identity.to_proto()),
            delegated_public_key: delegated_public_key.to_vec(),
            sequence,
            expires_at_unix_ms,
            reason: reason.to_string(),
        };
        let response = self
            .request_with_deadline(
                "IdentityService",
                "RevokeDelegation",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "IdentityService.RevokeDelegation")
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
        self.register_application_with_deadline(name, instance_id, endpoint_ids, protocols, None)
            .await
    }

    /// Registers application protocols with an absolute Control API deadline.
    pub async fn register_application_with_deadline(
        &mut self,
        name: &str,
        instance_id: [u8; 16],
        endpoint_ids: &[&[u8]],
        protocols: &[&str],
        deadline_unix_ms: Option<i64>,
    ) -> Result<AppHandle, ClientError> {
        Ok(self
            .register_application_with_options_and_deadline(
                name,
                instance_id,
                endpoint_ids,
                protocols,
                &[],
                false,
                deadline_unix_ms,
            )
            .await?
            .handle)
    }

    /// Registers an application while requesting a capability subset and an
    /// optional resumable principal. The returned grants are the daemon's
    /// effective subset after bearer authorization and resource constraints.
    pub async fn register_application_with_options(
        &mut self,
        name: &str,
        instance_id: [u8; 16],
        endpoint_ids: &[&[u8]],
        protocols: &[&str],
        requested_capabilities: &[v1::Capability],
        resumable: bool,
    ) -> Result<ApplicationRegistration, ClientError> {
        self.register_application_with_options_and_deadline(
            name,
            instance_id,
            endpoint_ids,
            protocols,
            requested_capabilities,
            resumable,
            None,
        )
        .await
    }

    /// Deadline-aware variant of [`Self::register_application_with_options`].
    #[allow(clippy::too_many_arguments)]
    pub async fn register_application_with_options_and_deadline(
        &mut self,
        name: &str,
        instance_id: [u8; 16],
        endpoint_ids: &[&[u8]],
        protocols: &[&str],
        requested_capabilities: &[v1::Capability],
        resumable: bool,
        deadline_unix_ms: Option<i64>,
    ) -> Result<ApplicationRegistration, ClientError> {
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
            requested_capabilities: requested_capabilities
                .iter()
                .map(|capability| *capability as i32)
                .collect(),
            resumable,
        };
        let response = self
            .request_with_deadline(
                "ApplicationService",
                "RegisterApplication",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "ApplicationService.RegisterApplication")?;
        let registered = v1::RegisterApplicationResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        let handle = registered
            .application_handle
            .as_ref()
            .map(|handle| AppHandle::from_proto_with_generation(handle, self.generation()))
            .ok_or_else(|| ClientError::Proto("application response has no handle".into()))?;
        Ok(ApplicationRegistration {
            handle,
            effective_grants: registered.effective_grants,
            resume_token: registered.resume_token,
        })
    }

    /// Removes an application registration. This is idempotent only when the
    /// daemon still owns the handle; stale generations are rejected locally.
    pub async fn unregister_application(
        &mut self,
        application: &AppHandle,
        close_owned_sessions: bool,
    ) -> Result<(), ClientError> {
        self.unregister_application_with_deadline(application, close_owned_sessions, None)
            .await
    }

    /// Removes an application registration with an absolute Control API
    /// deadline.
    pub async fn unregister_application_with_deadline(
        &mut self,
        application: &AppHandle,
        close_owned_sessions: bool,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        self.validate_handle(application)?;
        let request = v1::UnregisterApplicationRequest {
            application_handle: Some(application.to_proto()),
            close_owned_sessions,
        };
        let response = self
            .request_with_deadline(
                "ApplicationService",
                "UnregisterApplication",
                encode(&request)?,
                deadline_unix_ms,
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
        self.listen_with_deadline(application, endpoint_id, protocol_id, policy, None)
            .await
    }

    /// Binds a protocol to an endpoint with an absolute Control API deadline.
    pub async fn listen_with_deadline(
        &mut self,
        application: &AppHandle,
        endpoint_id: &[u8],
        protocol_id: &str,
        policy: &Policy,
        deadline_unix_ms: Option<i64>,
    ) -> Result<Listener, ClientError> {
        self.validate_handle(application)?;
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
            .request_with_deadline(
                "ApplicationService",
                "OpenListener",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "ApplicationService.OpenListener")?;
        let opened = v1::OpenListenerResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        let handle = opened
            .listener_handle
            .as_ref()
            .map(|handle| ListenerHandle::from_proto_with_generation(handle, self.generation()))
            .ok_or_else(|| ClientError::Proto("listener response has no handle".into()))?;
        Ok(Listener {
            handle,
            endpoint: EndpointHandle::with_generation(endpoint_id.to_vec(), self.generation()),
            protocol_id: protocol_id.to_string(),
        })
    }

    /// Closes a listener without affecting accepted sessions.
    pub async fn close_listener(&mut self, listener: &Listener) -> Result<(), ClientError> {
        self.close_listener_with_deadline(listener, None).await
    }

    /// Closes a listener with an absolute Control API deadline.
    pub async fn close_listener_with_deadline(
        &mut self,
        listener: &Listener,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        self.validate_handle(&listener.handle)?;
        let request = v1::CloseListenerRequest {
            listener_handle: Some(listener.handle.to_proto()),
            close_owned_sessions: false,
        };
        let response = self
            .request_with_deadline(
                "ApplicationService",
                "CloseListener",
                encode(&request)?,
                deadline_unix_ms,
            )
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
        self.validate_handle(application)?;
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
            .map(|handle| SessionHandle::from_proto_with_generation(handle, self.generation()))
            .ok_or_else(|| ClientError::Proto("connect response has no session handle".into()))
    }

    /// Connects using a specific local endpoint selected at registration.
    pub async fn connect_session_from_endpoint(
        &mut self,
        application: &AppHandle,
        local_endpoint: &EndpointHandle,
        destination_hint: &[u8],
        protocol_id: &str,
        policy: &Policy,
        deadline_unix_ms: Option<i64>,
    ) -> Result<SessionHandle, ClientError> {
        self.validate_handle(application)?;
        self.validate_handle(local_endpoint)?;
        validate_protocol_id(protocol_id)?;
        let request = v1::ConnectRequest {
            application_handle: Some(application.to_proto()),
            local_endpoint_id: local_endpoint.to_proto().value,
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
            .map(|handle| SessionHandle::from_proto_with_generation(handle, self.generation()))
            .ok_or_else(|| ClientError::Proto("connect response has no session handle".into()))
    }

    /// Adds a carrier path to an established session without creating a new
    /// application session. The daemon validates the path asynchronously and
    /// emits MIGRATE once `PATH_RESPONSE` arrives; the returned id is the
    /// session-scoped path selector.
    pub async fn migrate_session(
        &mut self,
        session: &SessionHandle,
        carrier_handle: &[u8],
        remote: &str,
        keep_old_path: bool,
        deadline_unix_ms: Option<i64>,
    ) -> Result<u64, ClientError> {
        self.validate_handle(session)?;
        if carrier_handle.is_empty() || remote.trim().is_empty() {
            return Err(ClientError::InvalidArgument);
        }
        let request = v1::MigrateSessionRequest {
            session_handle: Some(session.to_proto()),
            carrier_handle: Some(v1::OpaqueHandle {
                value: carrier_handle.to_vec(),
            }),
            remote: remote.to_string(),
            keep_old_path,
            deadline_ms: deadline_remaining(deadline_unix_ms).map_or(0, |remaining| {
                u64::try_from(remaining.as_millis().min(u128::from(u64::MAX))).unwrap_or(u64::MAX)
            }),
        };
        let response = self
            .request_with_deadline(
                "SessionService",
                "MigrateSession",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "SessionService.MigrateSession")?;
        let migrated = v1::MigrateSessionResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        Ok(migrated.path_id)
    }

    /// Accepts a pending incoming session owned by the application.
    pub async fn accept_session(
        &mut self,
        application: &AppHandle,
        pending_session: &SessionHandle,
    ) -> Result<SessionHandle, ClientError> {
        self.accept_session_with_deadline(application, pending_session, None)
            .await
    }

    /// Accepts a pending session with an absolute Control API deadline.
    pub async fn accept_session_with_deadline(
        &mut self,
        application: &AppHandle,
        pending_session: &SessionHandle,
        deadline_unix_ms: Option<i64>,
    ) -> Result<SessionHandle, ClientError> {
        self.validate_handle(application)?;
        self.validate_handle(pending_session)?;
        let request = v1::AcceptIncomingSessionRequest {
            application_handle: Some(application.to_proto()),
            pending_session_handle: Some(pending_session.to_proto()),
        };
        let response = self
            .request_with_deadline(
                "ApplicationService",
                "AcceptIncomingSession",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "ApplicationService.AcceptIncomingSession")?;
        let accepted = v1::AcceptIncomingSessionResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        accepted
            .session_handle
            .as_ref()
            .map(|handle| SessionHandle::from_proto_with_generation(handle, self.generation()))
            .ok_or_else(|| ClientError::Proto("accept response has no session handle".into()))
    }

    /// Rejects a pending incoming session and releases its application-owned
    /// transport state.
    pub async fn reject_session(
        &mut self,
        application: &AppHandle,
        pending_session: &SessionHandle,
        application_error_code: u64,
        reason: &str,
    ) -> Result<(), ClientError> {
        self.reject_session_with_deadline(
            application,
            pending_session,
            application_error_code,
            reason,
            None,
        )
        .await
    }

    /// Rejects a pending session with an absolute Control API deadline.
    pub async fn reject_session_with_deadline(
        &mut self,
        application: &AppHandle,
        pending_session: &SessionHandle,
        application_error_code: u64,
        reason: &str,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        self.validate_handle(application)?;
        self.validate_handle(pending_session)?;
        let request = v1::RejectIncomingSessionRequest {
            application_handle: Some(application.to_proto()),
            pending_session_handle: Some(pending_session.to_proto()),
            application_error_code,
            reason: reason.to_string(),
        };
        let response = self
            .request_with_deadline(
                "ApplicationService",
                "RejectIncomingSession",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "ApplicationService.RejectIncomingSession")
    }

    /// Opens one bidirectional or unidirectional stream.
    pub async fn open_stream(
        &mut self,
        application: &AppHandle,
        session: &SessionHandle,
        unidirectional: bool,
    ) -> Result<StreamHandle, ClientError> {
        self.open_stream_with_deadline(application, session, unidirectional, None)
            .await
    }

    /// Opens a stream with an absolute Control API deadline.
    pub async fn open_stream_with_deadline(
        &mut self,
        application: &AppHandle,
        session: &SessionHandle,
        unidirectional: bool,
        deadline_unix_ms: Option<i64>,
    ) -> Result<StreamHandle, ClientError> {
        self.validate_handle(application)?;
        self.validate_handle(session)?;
        let request = v1::OpenStreamRequest {
            application_handle: Some(application.to_proto()),
            session_handle: Some(session.to_proto()),
            unidirectional,
            initial_metadata: Vec::new(),
        };
        let response = self
            .request_with_deadline(
                "ApplicationService",
                "OpenStream",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "ApplicationService.OpenStream")?;
        let opened = v1::OpenStreamResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        opened
            .stream_handle
            .as_ref()
            .map(|handle| StreamHandle::from_proto_with_generation(handle, self.generation()))
            .ok_or_else(|| ClientError::Proto("stream response has no handle".into()))
    }

    /// Accepts one pending inbound stream.
    pub async fn accept_stream(
        &mut self,
        application: &AppHandle,
        pending_stream: &StreamHandle,
    ) -> Result<StreamHandle, ClientError> {
        self.accept_stream_with_deadline(application, pending_stream, None)
            .await
    }

    /// Accepts a pending inbound stream with an absolute Control API deadline.
    pub async fn accept_stream_with_deadline(
        &mut self,
        application: &AppHandle,
        pending_stream: &StreamHandle,
        deadline_unix_ms: Option<i64>,
    ) -> Result<StreamHandle, ClientError> {
        self.validate_handle(application)?;
        self.validate_handle(pending_stream)?;
        let request = v1::AcceptStreamRequest {
            application_handle: Some(application.to_proto()),
            pending_stream_handle: Some(pending_stream.to_proto()),
        };
        let response = self
            .request_with_deadline(
                "ApplicationService",
                "AcceptStream",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "ApplicationService.AcceptStream")?;
        let accepted = v1::AcceptStreamResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        accepted
            .stream_handle
            .as_ref()
            .map(|handle| StreamHandle::from_proto_with_generation(handle, self.generation()))
            .ok_or_else(|| ClientError::Proto("accept response has no stream handle".into()))
    }

    /// Rejects one pending inbound stream with an application error code.
    pub async fn reject_stream(
        &mut self,
        pending_stream: &StreamHandle,
        application_error_code: u64,
    ) -> Result<(), ClientError> {
        self.reject_stream_with_deadline(pending_stream, application_error_code, None)
            .await
    }

    /// Rejects a pending inbound stream with an absolute Control API deadline.
    pub async fn reject_stream_with_deadline(
        &mut self,
        pending_stream: &StreamHandle,
        application_error_code: u64,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        self.validate_handle(pending_stream)?;
        let request = v1::RejectStreamRequest {
            pending_stream_handle: Some(pending_stream.to_proto()),
            application_error_code,
        };
        let response = self
            .request_with_deadline(
                "ApplicationService",
                "RejectStream",
                encode(&request)?,
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "ApplicationService.RejectStream")
    }

    /// Writes bounded chunks and returns the number of bytes accepted by the
    /// daemon. A successful return means local ownership only.
    pub async fn write_stream(
        &mut self,
        stream: &StreamHandle,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, ClientError> {
        self.write_stream_with_deadline(stream, data, fin, None)
            .await
    }

    /// Writes bounded chunks with an absolute Control API deadline. The
    /// daemon backend enforces it on every chunk; the embedded backend
    /// applies the same check before mutating stream state.
    pub async fn write_stream_with_deadline(
        &mut self,
        stream: &StreamHandle,
        data: &[u8],
        fin: bool,
        deadline_unix_ms: Option<i64>,
    ) -> Result<usize, ClientError> {
        self.validate_handle(stream)?;
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
                .request_with_deadline(
                    "ApplicationService",
                    "WriteStream",
                    encode(&request)?,
                    deadline_unix_ms,
                )
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
        self.read_stream_with_deadline(stream, maximum_bytes, wait_for_data, None)
            .await
    }

    /// Reads a bounded chunk with an absolute Control API deadline.
    pub async fn read_stream_with_deadline(
        &mut self,
        stream: &StreamHandle,
        maximum_bytes: usize,
        wait_for_data: bool,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(Vec<u8>, bool), ClientError> {
        self.validate_handle(stream)?;
        let maximum_bytes = maximum_bytes.min(SDK_MAX_CHUNK_SIZE);
        let request = v1::ReadStreamRequest {
            stream_handle: Some(stream.to_proto()),
            maximum_bytes: u32::try_from(maximum_bytes).unwrap_or(u32::MAX),
            wait_for_data,
        };
        let embedded_wait = self.is_embedded()
            && wait_for_data
            && deadline_unix_ms.is_some_and(|deadline| deadline > 0);
        let response = loop {
            let response = self
                .request_with_deadline(
                    "ApplicationService",
                    "ReadStream",
                    encode(&request)?,
                    deadline_unix_ms,
                )
                .await?;
            let status = response
                .status
                .as_ref()
                .map_or(v1::StatusCode::Ok as i32, |status| status.code);
            if embedded_wait && status == v1::StatusCode::Unavailable as i32 {
                let remaining = deadline_remaining(deadline_unix_ms);
                if remaining.map_or(true, |remaining| remaining.is_zero()) {
                    return Err(ClientError::DeadlineExceeded);
                }
                tokio::time::sleep(Duration::from_millis(
                    remaining.map_or(1, |remaining| remaining.as_millis().min(1) as u64),
                ))
                .await;
                continue;
            }
            break response;
        };
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
        self.close_stream_send_with_deadline(stream, None).await
    }

    /// Sends a FIN on a stream with an absolute Control API deadline.
    pub async fn close_stream_send_with_deadline(
        &mut self,
        stream: &StreamHandle,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        self.validate_handle(stream)?;
        self.stream_control_with_deadline(
            "CloseStreamSend",
            v1::CloseStreamSendRequest {
                stream_handle: Some(stream.to_proto()),
            }
            .encode_to_vec(),
            "ApplicationService.CloseStreamSend",
            deadline_unix_ms,
        )
        .await
    }

    /// Resets one stream direction.
    pub async fn reset_stream(
        &mut self,
        stream: &StreamHandle,
        error_code: u64,
    ) -> Result<(), ClientError> {
        self.reset_stream_with_deadline(stream, error_code, None)
            .await
    }

    /// Resets one stream direction with an absolute Control API deadline.
    pub async fn reset_stream_with_deadline(
        &mut self,
        stream: &StreamHandle,
        error_code: u64,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        self.validate_handle(stream)?;
        self.stream_control_with_deadline(
            "ResetStream",
            v1::ResetStreamRequest {
                stream_handle: Some(stream.to_proto()),
                application_error_code: error_code,
            }
            .encode_to_vec(),
            "ApplicationService.ResetStream",
            deadline_unix_ms,
        )
        .await
    }

    /// Requests that the peer stop sending on one stream.
    pub async fn stop_stream(
        &mut self,
        stream: &StreamHandle,
        error_code: u64,
    ) -> Result<(), ClientError> {
        self.stop_stream_with_deadline(stream, error_code, None)
            .await
    }

    /// Requests that the peer stop sending with an absolute Control API
    /// deadline.
    pub async fn stop_stream_with_deadline(
        &mut self,
        stream: &StreamHandle,
        error_code: u64,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        self.validate_handle(stream)?;
        self.stream_control_with_deadline(
            "StopStream",
            v1::StopStreamRequest {
                stream_handle: Some(stream.to_proto()),
                application_error_code: error_code,
            }
            .encode_to_vec(),
            "ApplicationService.StopStream",
            deadline_unix_ms,
        )
        .await
    }

    async fn stream_control_with_deadline(
        &mut self,
        method: &str,
        payload: Vec<u8>,
        label: &str,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        let response = self
            .request_with_deadline("ApplicationService", method, payload, deadline_unix_ms)
            .await?;
        require_ok(&response, label)
    }

    /// Closes the transport link represented by a session handle.
    pub async fn close_link(
        &mut self,
        session: &SessionHandle,
        reason: &str,
    ) -> Result<(), ClientError> {
        self.close_link_with_deadline(session, reason, None).await
    }

    /// Closes a transport link with an absolute Control API deadline.
    pub async fn close_link_with_deadline(
        &mut self,
        session: &SessionHandle,
        reason: &str,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        self.validate_handle(session)?;
        let response = self
            .request_with_deadline(
                "CarrierService",
                "CloseLink",
                v1::CloseLinkRequest {
                    link_handle: Some(session.to_proto()),
                    reason: reason.to_string(),
                }
                .encode_to_vec(),
                deadline_unix_ms,
            )
            .await?;
        require_ok(&response, "CarrierService.CloseLink")
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
        self.send_datagram_with_deadline(session, context_id, data, lifetime_ms, request_ack, None)
            .await
    }

    /// Sends one datagram with an absolute Control API deadline.
    pub async fn send_datagram_with_deadline(
        &mut self,
        session: &SessionHandle,
        context_id: u64,
        data: &[u8],
        lifetime_ms: u64,
        request_ack: bool,
        deadline_unix_ms: Option<i64>,
    ) -> Result<u64, ClientError> {
        self.validate_handle(session)?;
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
            .request_with_deadline(
                "ApplicationService",
                "SendDatagram",
                encode(&request)?,
                deadline_unix_ms,
            )
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
        self.receive_datagram_with_deadline(
            application,
            session,
            maximum_bytes,
            wait_for_data,
            None,
        )
        .await
    }

    /// Receives one datagram with an absolute Control API deadline.
    pub async fn receive_datagram_with_deadline(
        &mut self,
        application: &AppHandle,
        session: &SessionHandle,
        maximum_bytes: usize,
        wait_for_data: bool,
        deadline_unix_ms: Option<i64>,
    ) -> Result<Datagram, ClientError> {
        self.validate_handle(application)?;
        self.validate_handle(session)?;
        let request = v1::ReceiveDatagramRequest {
            application_handle: Some(application.to_proto()),
            session_handle: Some(session.to_proto()),
            maximum_bytes: u32::try_from(maximum_bytes.min(SDK_MAX_DATAGRAM_SIZE))
                .unwrap_or(u32::MAX),
            wait_for_data,
        };
        let embedded_wait = self.is_embedded()
            && wait_for_data
            && deadline_unix_ms.is_some_and(|deadline| deadline > 0);
        let response = loop {
            let response = self
                .request_with_deadline(
                    "ApplicationService",
                    "ReceiveDatagram",
                    encode(&request)?,
                    deadline_unix_ms,
                )
                .await?;
            let status = response
                .status
                .as_ref()
                .map_or(v1::StatusCode::Ok as i32, |status| status.code);
            if embedded_wait && status == v1::StatusCode::Unavailable as i32 {
                let remaining = deadline_remaining(deadline_unix_ms);
                if remaining.map_or(true, |remaining| remaining.is_zero()) {
                    return Err(ClientError::DeadlineExceeded);
                }
                tokio::time::sleep(Duration::from_millis(
                    remaining.map_or(1, |remaining| remaining.as_millis().min(1) as u64),
                ))
                .await;
                continue;
            }
            break response;
        };
        require_ok(&response, "ApplicationService.ReceiveDatagram")?;
        let received = v1::ReceiveDatagramResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        let Some(received_session) = received
            .session_handle
            .as_ref()
            .map(|handle| SessionHandle::from_proto_with_generation(handle, self.generation()))
        else {
            return Err(if wait_for_data {
                ClientError::Unavailable
            } else {
                ClientError::WouldBlock
            });
        };
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

fn deadline_remaining(deadline_unix_ms: Option<i64>) -> Option<Duration> {
    let deadline = deadline_unix_ms.filter(|deadline| *deadline > 0)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX);
    let remaining = deadline.saturating_sub(now);
    if remaining <= 0 {
        return Some(Duration::ZERO);
    }
    Some(Duration::from_millis(
        u64::try_from(remaining).unwrap_or(u64::MAX),
    ))
}
