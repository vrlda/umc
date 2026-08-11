//! In-process SDK backend (sdk.md §26).
//!
//! The embedded backend keeps the same protobuf-shaped request boundary as
//! the daemon client, but executes it against an in-process core-owned state
//! table.  The first slice is deliberately loopback-only: it gives embedded
//! applications real endpoint, application, listener, stream, and datagram
//! handles while transport/carrier attachment remains an explicit adapter.
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use prost::Message;
use rand_core::RngCore;
use umc_carrier::types::LinkEvent;
use umc_control::events::{event_filter_digest, EventResumeCursor, EVENT_CURSOR_TTL_MS};
use umc_control::proto::umc::api::v1 as api;
use umc_core::node::{Node, NodeConfig, NodeIdentity};
use umc_core::trust::{TrustState, TrustStore};
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_storage::store::Store;
use umc_types::runtime::{Clock, EntropySource, Instant};

use crate::client::ClientError;
use crate::embedded_transport::{
    encode_datagram_frame, encode_stream_frame, EmbeddedFrame, EmbeddedTransport, PendingDelivery,
    TransportError, TransportPoll,
};
use crate::events::Event;

const EMBEDDED_EVENT_MAX_BACKLOG: usize = 1_024;
const EMBEDDED_EVENT_MAX_BACKLOG_BYTES: usize = 4 * 1024 * 1024;
const EMBEDDED_PRIMARY_RECORD: &[u8] = b"embedded/node-identity";
const EMBEDDED_ENDPOINT_RECORD_PREFIX: &[u8] = b"embedded/endpoint/";

struct EmbeddedStorage {
    keystore: umc_storage::keystore::Keystore,
    store: Arc<umc_storage::sqlite::SqliteStore>,
}

struct CarrierHandle(Arc<dyn umc_carrier::Carrier + Send + Sync>);

impl std::fmt::Debug for CarrierHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CarrierHandle")
            .field("type_id", &self.0.type_id().0)
            .finish()
    }
}

impl std::fmt::Debug for EmbeddedStorage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EmbeddedStorage")
            .field("keystore", &"protected")
            .field("store", &"sqlite")
            .finish()
    }
}

#[derive(Debug)]
struct PersistedEndpoint {
    label: String,
    kind: i32,
    identity: NodeIdentity,
}

impl EmbeddedStorage {
    fn open(
        root: &Path,
        password: &[u8],
    ) -> Result<(Self, NodeIdentity, Vec<PersistedEndpoint>), String> {
        std::fs::create_dir_all(root)
            .map_err(|error| format!("create embedded storage: {error}"))?;
        let keystore = umc_storage::keystore::Keystore::open(root.join("keystore.ks"), password)
            .map_err(|error| format!("open embedded keystore: {error:?}"))?;
        let identity = match keystore.load(
            umc_storage::keystore::KeyClass::IdentitySigning,
            EMBEDDED_PRIMARY_RECORD,
        ) {
            Ok(seeds) => identity_from_seeds(&seeds, "embedded primary identity")?,
            Err(umc_storage::keystore::KeystoreError::UnsupportedClass) => {
                let identity = NodeIdentity::generate(&EmbeddedEntropy);
                keystore
                    .store(
                        umc_storage::keystore::KeyClass::IdentitySigning,
                        EMBEDDED_PRIMARY_RECORD,
                        &identity_seeds(&identity),
                    )
                    .map_err(|error| format!("store embedded primary identity: {error:?}"))?;
                identity
            }
            Err(error) => return Err(format!("load embedded primary identity: {error:?}")),
        };
        let store = Arc::new(
            umc_storage::sqlite::SqliteStore::open(&root.join("node.db"))
                .map_err(|error| format!("open embedded store: {error:?}"))?,
        );
        let mut endpoints = Vec::new();
        for entry in store
            .scan(umc_storage::store::Namespace::Identity)
            .map_err(|error| format!("scan embedded identities: {error:?}"))?
        {
            let Some(endpoint_id) = entry.key.strip_prefix(b"endpoint/") else {
                continue;
            };
            if endpoint_id.len() != 32 {
                return Err("embedded identity record has invalid endpoint id".into());
            }
            let (kind, label) = decode_endpoint_metadata(&entry.value)?;
            if endpoint_id == identity.endpoint_id() {
                continue;
            }
            let mut record_name = EMBEDDED_ENDPOINT_RECORD_PREFIX.to_vec();
            record_name.extend_from_slice(endpoint_id);
            let seeds = keystore
                .load(
                    umc_storage::keystore::KeyClass::IdentitySigning,
                    &record_name,
                )
                .map_err(|error| format!("load embedded endpoint identity: {error:?}"))?;
            let endpoint_identity = identity_from_seeds(&seeds, "embedded endpoint identity")?;
            if endpoint_identity.endpoint_id().as_slice() != endpoint_id {
                return Err("embedded endpoint id does not match its key material".into());
            }
            endpoints.push(PersistedEndpoint {
                label,
                kind,
                identity: endpoint_identity,
            });
        }
        Ok((Self { keystore, store }, identity, endpoints))
    }

    fn persist_new_identity(
        &self,
        identity: &NodeIdentity,
        label: &str,
        kind: i32,
    ) -> Result<(), String> {
        let endpoint_id = identity.endpoint_id();
        let mut record_name = EMBEDDED_ENDPOINT_RECORD_PREFIX.to_vec();
        record_name.extend_from_slice(&endpoint_id);
        self.keystore
            .store(
                umc_storage::keystore::KeyClass::IdentitySigning,
                &record_name,
                &identity_seeds(identity),
            )
            .map_err(|error| format!("store embedded endpoint identity: {error:?}"))?;
        self.store
            .put(
                umc_storage::store::Namespace::Identity,
                &endpoint_metadata_key(&endpoint_id),
                &encode_endpoint_metadata(kind, label)?,
            )
            .map_err(|error| format!("store embedded endpoint metadata: {error:?}"))
    }

    fn persist_primary_metadata(
        &self,
        endpoint_id: &[u8],
        label: &str,
        kind: i32,
    ) -> Result<(), String> {
        self.store
            .put(
                umc_storage::store::Namespace::Identity,
                &endpoint_metadata_key(endpoint_id),
                &encode_endpoint_metadata(kind, label)?,
            )
            .map_err(|error| format!("store embedded primary metadata: {error:?}"))
    }
}

/// Configuration for an in-process SDK backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedConfig {
    /// Label assigned to the initial in-process endpoint.
    pub endpoint_label: String,
}

impl Default for EmbeddedConfig {
    fn default() -> Self {
        Self {
            endpoint_label: "default".into(),
        }
    }
}

#[derive(Debug)]
struct EmbeddedEndpoint {
    summary: api::IdentitySummary,
    /// Additional endpoint identities are kept inside the backend; the
    /// initial endpoint is the identity already owned by `Node`.
    _identity: Option<NodeIdentity>,
}

#[derive(Debug)]
struct EmbeddedApplication {
    endpoint_ids: Vec<Vec<u8>>,
    protocols: HashSet<String>,
}

#[derive(Debug)]
struct EmbeddedSession {
    application: Vec<u8>,
    local_endpoint_id: Vec<u8>,
    remote_endpoint_id: Vec<u8>,
    protocol_id: String,
    streams: Vec<Vec<u8>>,
    datagrams: VecDeque<EmbeddedDatagram>,
    transport: EmbeddedTransport,
    closed: bool,
}

#[derive(Debug)]
struct EmbeddedStream {
    stream_id: u64,
    session_handle: Vec<u8>,
    bidirectional: bool,
    buffer: VecDeque<u8>,
    send_closed: bool,
    reset: Option<u64>,
    stopped: bool,
    bytes_sent: u64,
    bytes_received: u64,
}

#[derive(Debug)]
struct EmbeddedDatagram {
    context_id: u64,
    data: Vec<u8>,
    expired: bool,
}

#[derive(Debug, Clone)]
struct EmbeddedCarrierInstance {
    type_id: String,
    label: String,
    state: i32,
    options: Vec<api::ConfigEntry>,
    revision: u64,
}

#[derive(Debug)]
struct EmbeddedRawLink {
    carrier_handle: Vec<u8>,
    transport: EmbeddedTransport,
}

#[derive(Debug)]
struct EmbeddedSubscription {
    filter: api::EventFilter,
    next_sequence: u64,
    queue: VecDeque<api::Event>,
    queue_bytes: usize,
    /// Sequence and payload size for events handed to the embedded caller
    /// but not acknowledged yet. These bytes remain charged to the same
    /// bounded backlog as queued events, matching the daemon event bus.
    in_flight: VecDeque<(u64, usize)>,
    in_flight_bytes: usize,
    out_of_sync_from: Option<u64>,
    out_of_sync_to: Option<u64>,
}

/// Mutable in-process backend used by [`crate::Client`].
#[derive(Debug)]
pub(crate) struct EmbeddedBackend {
    generation: u64,
    next_handle: u64,
    next_stream_id: u64,
    next_datagram_id: u64,
    carrier_handle: Vec<u8>,
    carrier_instances: HashMap<Vec<u8>, EmbeddedCarrierInstance>,
    /// Keeps the core runtime and its identity abstraction owned by the
    /// backend even while this bounded slice uses loopback data structures.
    node: Node,
    carrier: CarrierHandle,
    storage: Option<EmbeddedStorage>,
    endpoints: HashMap<Vec<u8>, EmbeddedEndpoint>,
    endpoint_by_label: HashMap<String, Vec<u8>>,
    applications: HashMap<Vec<u8>, EmbeddedApplication>,
    listeners: HashSet<Vec<u8>>,
    sessions: HashMap<Vec<u8>, EmbeddedSession>,
    raw_links: HashMap<Vec<u8>, EmbeddedRawLink>,
    streams: HashMap<Vec<u8>, EmbeddedStream>,
    subscriptions: HashMap<Vec<u8>, EmbeddedSubscription>,
    event_cursor_key: [u8; 32],
    event_history_next_sequence: u64,
    event_history: VecDeque<(u64, api::Event)>,
    event_history_bytes: usize,
}

impl EmbeddedBackend {
    pub(crate) fn new(config: &EmbeddedConfig) -> Result<Self, ClientError> {
        Self::new_inner(
            config,
            None,
            Arc::new(crate::embedded_transport::LoopbackCarrier::default()),
        )
    }

    pub(crate) fn new_with_carrier(
        config: &EmbeddedConfig,
        carrier: Arc<dyn umc_carrier::Carrier + Send + Sync>,
    ) -> Result<Self, ClientError> {
        Self::new_inner(config, None, carrier)
    }

    pub(crate) fn new_with_storage(
        config: &EmbeddedConfig,
        storage_root: PathBuf,
        storage_password: Vec<u8>,
    ) -> Result<Self, ClientError> {
        Self::new_inner(
            config,
            Some((storage_root, storage_password)),
            Arc::new(crate::embedded_transport::LoopbackCarrier::default()),
        )
    }

    fn new_inner(
        config: &EmbeddedConfig,
        storage_config: Option<(PathBuf, Vec<u8>)>,
        carrier: Arc<dyn umc_carrier::Carrier + Send + Sync>,
    ) -> Result<Self, ClientError> {
        if config.endpoint_label.trim().is_empty() {
            return Err(ClientError::InvalidArgument);
        }
        let entropy = Arc::new(EmbeddedEntropy);
        let (storage, identity, persisted_endpoints) = match storage_config {
            Some((root, password)) => {
                let (storage, identity, endpoints) =
                    EmbeddedStorage::open(&root, &password).map_err(ClientError::Internal)?;
                (Some(storage), identity, endpoints)
            }
            None => (None, NodeIdentity::generate(entropy.as_ref()), Vec::new()),
        };
        if persisted_endpoints
            .iter()
            .any(|endpoint| endpoint.label == config.endpoint_label)
        {
            return Err(ClientError::InvalidArgument);
        }
        let endpoint_id = identity.endpoint_id().to_vec();
        let generation = generation_for(&endpoint_id);
        let mut event_cursor_key = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut event_cursor_key);
        let node = Node::new(
            NodeConfig {
                identity,
                dcid: endpoint_id[..8].to_vec(),
            },
            Arc::new(EmbeddedClock),
            entropy,
        );
        let mut backend = Self {
            generation,
            next_handle: 0,
            next_stream_id: 0,
            next_datagram_id: 0,
            carrier_handle: b"embedded-carrier".to_vec(),
            carrier_instances: HashMap::new(),
            node,
            carrier: CarrierHandle(carrier),
            storage,
            endpoints: HashMap::new(),
            endpoint_by_label: HashMap::new(),
            applications: HashMap::new(),
            listeners: HashSet::new(),
            sessions: HashMap::new(),
            raw_links: HashMap::new(),
            streams: HashMap::new(),
            subscriptions: HashMap::new(),
            event_cursor_key,
            event_history_next_sequence: 0,
            event_history: VecDeque::new(),
            event_history_bytes: 0,
        };
        let carrier_type = backend.carrier.0.type_id().0;
        backend.carrier_instances.insert(
            backend.carrier_handle.clone(),
            EmbeddedCarrierInstance {
                type_id: carrier_type,
                label: "embedded".into(),
                state: api::CarrierInstanceState::Running as i32,
                options: Vec::new(),
                revision: 1,
            },
        );
        let _ = backend.create_endpoint(
            config.endpoint_label.clone(),
            api::IdentityKind::UserEndpoint as i32,
            None,
        )?;
        if let Some(storage) = backend.storage.as_ref() {
            storage
                .persist_primary_metadata(
                    &endpoint_id,
                    &config.endpoint_label,
                    api::IdentityKind::UserEndpoint as i32,
                )
                .map_err(ClientError::Internal)?;
        }
        for persisted in persisted_endpoints {
            backend.create_endpoint(persisted.label, persisted.kind, Some(persisted.identity))?;
        }
        Ok(backend)
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn request_raw(
        &mut self,
        service: &str,
        method: &str,
        payload: &[u8],
        deadline_unix_ms: Option<i64>,
    ) -> (i32, Vec<u8>) {
        if let Some(deadline) = deadline_unix_ms {
            if deadline < 0 {
                return (api::StatusCode::InvalidArgument as i32, Vec::new());
            }
            if deadline > 0 && deadline <= now_unix_ms() {
                return (api::StatusCode::DeadlineExceeded as i32, Vec::new());
            }
        }
        match (service, method) {
            ("IdentityService", "CreateIdentity") => self.create_identity(payload),
            ("IdentityService", "ListIdentities") => self.list_identities(payload),
            ("IdentityService", "GetIdentity") => self.get_identity(payload),
            ("IdentityService", "ImportIdentity") => self.import_identity(payload),
            ("ApplicationService", "RegisterApplication") => self.register_application(payload),
            ("ApplicationService", "UnregisterApplication") => self.unregister_application(payload),
            ("ApplicationService", "OpenListener") => self.open_listener(payload),
            ("ApplicationService", "CloseListener") => self.close_listener(payload),
            ("ApplicationService", "Connect") => self.connect(payload),
            ("ApplicationService", "AcceptIncomingSession") => {
                self.accept_incoming_session(payload)
            }
            ("ApplicationService", "RejectIncomingSession") => {
                self.reject_incoming_session(payload)
            }
            ("SessionService", "MigrateSession") => self.migrate_session(payload),
            ("ApplicationService", "AcceptStream") => self.accept_stream(payload),
            ("ApplicationService", "RejectStream") => self.reject_stream(payload),
            ("ApplicationService", "OpenStream") => self.open_stream(payload),
            ("ApplicationService", "ReadStream") => self.read_stream(payload),
            ("ApplicationService", "WriteStream") => self.write_stream(payload),
            ("ApplicationService", "CloseStreamSend") => self.close_stream(payload),
            ("ApplicationService", "ResetStream") => self.reset_stream(payload),
            ("ApplicationService", "StopStream") => self.stop_stream(payload),
            ("ApplicationService", "SendDatagram") => self.send_datagram(payload),
            ("ApplicationService", "ReceiveDatagram") => self.receive_datagram(payload),
            ("CarrierService", "ListCarrierTypes") => self.list_carrier_types(payload),
            ("CarrierService", "ListCarrierInstances") => self.list_carrier_instances(payload),
            ("CarrierService", "GetCarrierInstance") => self.get_carrier_instance(payload),
            ("CarrierService", "CreateCarrierInstance") => self.create_carrier_instance(payload),
            ("CarrierService", "UpdateCarrierInstance") => self.update_carrier_instance(payload),
            ("CarrierService", "StartCarrier") => self.start_carrier(payload),
            ("CarrierService", "StopCarrier") => self.stop_carrier(payload),
            ("CarrierService", "DeleteCarrierInstance") => self.delete_carrier_instance(payload),
            ("CarrierService", "Dial") => self.dial_carrier(payload),
            ("CarrierService", "ListLinks") => self.list_links(payload),
            ("CarrierService", "CloseLink") => self.close_link(payload),
            ("EventService", "Subscribe") => self.subscribe_events(payload),
            ("EventService", "Unsubscribe") => self.unsubscribe_events(payload),
            _ => (api::StatusCode::Unimplemented as i32, Vec::new()),
        }
    }

    fn create_endpoint(
        &mut self,
        label: String,
        kind: i32,
        identity: Option<NodeIdentity>,
    ) -> Result<api::IdentitySummary, ClientError> {
        self.create_endpoint_with_event(label, kind, identity, "identity_changed")
    }

    fn create_endpoint_with_event(
        &mut self,
        label: String,
        kind: i32,
        identity: Option<NodeIdentity>,
        event_payload_type: &str,
    ) -> Result<api::IdentitySummary, ClientError> {
        if label.trim().is_empty() || self.endpoint_by_label.contains_key(&label) {
            return Err(ClientError::InvalidArgument);
        }
        let endpoint_id = identity.as_ref().map_or_else(
            || self.node.config.identity.endpoint_id().to_vec(),
            |identity| identity.endpoint_id().to_vec(),
        );
        let handle = self.next_handle(16);
        let summary = api::IdentitySummary {
            identity_handle: Some(api::OpaqueHandle {
                value: handle.clone(),
            }),
            endpoint_id: endpoint_id.clone(),
            kind,
            label: label.clone(),
            binding_sequence: 0,
            binding_not_after_unix_ms: i64::MAX,
            secret_available: true,
            revision: Some(api::ResourceRevision { value: 1 }),
        };
        self.endpoint_by_label.insert(label, handle.clone());
        self.endpoints.insert(
            handle,
            EmbeddedEndpoint {
                summary: summary.clone(),
                _identity: identity,
            },
        );
        self.publish_event(
            api::EventType::IdentityChanged,
            api::EventClass::State,
            summary
                .identity_handle
                .as_ref()
                .map(|value| value.value.clone()),
            summary.endpoint_id.clone(),
            event_payload_type,
            summary.label.as_bytes().to_vec(),
        );
        Ok(summary)
    }

    fn create_identity(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::CreateIdentityRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if request.label.trim().is_empty() || self.endpoint_by_label.contains_key(&request.label) {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let entropy = EmbeddedEntropy;
        let label = request.label.clone();
        let identity = NodeIdentity::generate(&entropy);
        if let Some(storage) = self.storage.as_ref() {
            if storage
                .persist_new_identity(&identity, &label, request.kind)
                .is_err()
            {
                return (api::StatusCode::Internal as i32, Vec::new());
            }
        }
        let Ok(summary) = self.create_endpoint(request.label, request.kind, Some(identity)) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        encoded_ok(&api::CreateIdentityResponse {
            identity: Some(summary),
            public_binding: Vec::new(),
        })
    }

    fn list_identities(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        if api::ListIdentitiesRequest::decode(payload).is_err() {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let mut identities: Vec<_> = self
            .endpoints
            .values()
            .map(|endpoint| endpoint.summary.clone())
            .collect();
        identities.sort_by(|left, right| left.label.cmp(&right.label));
        encoded_ok(&api::ListIdentitiesResponse {
            identities,
            page: None,
        })
    }

    fn get_identity(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::GetIdentityRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let endpoint = match request.identity {
            Some(api::get_identity_request::Identity::Handle(handle)) => {
                self.endpoints.get(&handle.value)
            }
            Some(api::get_identity_request::Identity::EndpointId(endpoint_id)) => self
                .endpoints
                .values()
                .find(|endpoint| endpoint.summary.endpoint_id == endpoint_id),
            None => None,
        };
        let Some(endpoint) = endpoint else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        encoded_ok(&api::GetIdentityResponse {
            identity: Some(endpoint.summary.clone()),
            public_binding: Vec::new(),
        })
    }

    fn import_identity(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::ImportIdentityRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if request.passphrase.is_empty() == request.os_key_reference.is_empty() {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let open_result = if request.passphrase.is_empty() {
            umc_storage::secret_export::open_with_keychain(
                &umc_storage::keychain::OsKeychain,
                &request.os_key_reference,
                &request.encrypted_export,
            )
        } else {
            umc_storage::secret_export::open(&request.passphrase, &request.encrypted_export)
        };
        let seeds = match open_result {
            Ok(seeds) => seeds,
            Err(umc_storage::secret_export::SecretExportError::AuthenticationFailed) => {
                return (api::StatusCode::PermissionDenied as i32, Vec::new());
            }
            Err(_) => return (api::StatusCode::InvalidArgument as i32, Vec::new()),
        };
        if seeds.len() != 64 {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let identity_seed: [u8; 32] = seeds[..32]
            .try_into()
            .expect("validated identity seed length");
        let static_seed: [u8; 32] = seeds[32..]
            .try_into()
            .expect("validated static handshake seed length");
        let identity = NodeIdentity {
            identity: IdentityKeyPair::from_seed(identity_seed),
            static_handshake: StaticHandshakeKeyPair::from_seed(static_seed),
        };

        // Keep validate-only imports side-effect free while still returning
        // the same public summary shape as a committed secondary identity.
        if request.validate_only {
            let handle = self.peek_next_handle(16);
            let summary = api::IdentitySummary {
                identity_handle: Some(api::OpaqueHandle { value: handle }),
                endpoint_id: identity.endpoint_id().to_vec(),
                kind: api::IdentityKind::UserEndpoint as i32,
                label: "imported".into(),
                binding_sequence: 0,
                binding_not_after_unix_ms: i64::MAX,
                secret_available: true,
                revision: Some(api::ResourceRevision { value: 1 }),
            };
            return encoded_ok(&api::ImportIdentityResponse {
                identity: Some(summary),
            });
        }

        let label = self.next_import_label();
        if let Some(storage) = self.storage.as_ref() {
            if storage
                .persist_new_identity(&identity, &label, api::IdentityKind::UserEndpoint as i32)
                .is_err()
            {
                return (api::StatusCode::Internal as i32, Vec::new());
            }
        }
        let Ok(summary) = self.create_endpoint_with_event(
            label,
            api::IdentityKind::UserEndpoint as i32,
            Some(identity),
            "identity_secret_imported",
        ) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        encoded_ok(&api::ImportIdentityResponse {
            identity: Some(summary),
        })
    }

    fn next_import_label(&self) -> String {
        let mut label = "imported".to_string();
        let mut suffix = 0u64;
        while self.endpoint_by_label.contains_key(&label) {
            suffix = suffix.saturating_add(1);
            label = format!("imported-{suffix}");
        }
        label
    }

    fn register_application(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::RegisterApplicationRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if request.application_name.trim().is_empty() || request.requested_protocol_ids.is_empty() {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        if request.requested_endpoint_ids.iter().any(|endpoint| {
            !self
                .endpoints
                .values()
                .any(|known| known.summary.endpoint_id == *endpoint)
        }) {
            return (api::StatusCode::NotFound as i32, Vec::new());
        }
        let application = self.next_handle(16);
        let endpoint_ids = request.requested_endpoint_ids;
        let protocols = request.requested_protocol_ids;
        self.applications.insert(
            application.clone(),
            EmbeddedApplication {
                endpoint_ids: endpoint_ids.clone(),
                protocols: protocols.into_iter().collect(),
            },
        );
        self.publish_event(
            api::EventType::NodeState,
            api::EventClass::State,
            Some(application.clone()),
            endpoint_ids.first().cloned().unwrap_or_default(),
            "application_registered",
            Vec::new(),
        );
        encoded_ok(&api::RegisterApplicationResponse {
            application_handle: Some(api::OpaqueHandle { value: application }),
            effective_grants: Vec::new(),
            resume_token: Vec::new(),
        })
    }

    fn unregister_application(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::UnregisterApplicationRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.application_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let application_id = handle.value.clone();
        if self.applications.remove(&application_id).is_none() {
            return (api::StatusCode::NotFound as i32, Vec::new());
        }
        self.listeners.remove(&application_id);
        // The embedded backend has no detached transport task to drain. Its
        // application-owned state is therefore removed immediately, matching
        // the daemon's application-data cleanup while avoiding stale stream
        // and datagram handles after unregister.
        let _ = request.close_owned_sessions;
        let sessions: Vec<Vec<u8>> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.application == application_id)
            .map(|(handle, _)| handle.clone())
            .collect();
        for session_handle in sessions {
            if let Some(session) = self.sessions.remove(&session_handle) {
                for stream_handle in session.streams {
                    self.streams.remove(&stream_handle);
                }
            }
        }
        self.publish_event(
            api::EventType::NodeState,
            api::EventClass::State,
            Some(application_id.clone()),
            Vec::new(),
            "application_unregistered",
            Vec::new(),
        );
        encoded_ok(&api::UnregisterApplicationResponse {})
    }

    fn open_listener(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::OpenListenerRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(application) = request.application_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(app) = self.applications.get(&application.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if !app.protocols.contains(&request.protocol_id)
            || !app
                .endpoint_ids
                .iter()
                .any(|endpoint| endpoint == &request.endpoint_id)
        {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let application_id = application.value.clone();
        if !self.listeners.insert(application_id.clone()) {
            return (api::StatusCode::AlreadyExists as i32, Vec::new());
        }
        self.publish_event(
            api::EventType::NodeState,
            api::EventClass::State,
            Some(application_id.clone()),
            request.endpoint_id.clone(),
            "listener_opened",
            request.protocol_id.as_bytes().to_vec(),
        );
        encoded_ok(&api::OpenListenerResponse {
            listener_handle: Some(api::OpaqueHandle {
                value: application_id,
            }),
        })
    }

    fn close_listener(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::CloseListenerRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.listener_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let listener_id = handle.value.clone();
        if !self.listeners.remove(&listener_id) {
            return (api::StatusCode::NotFound as i32, Vec::new());
        }
        self.publish_event(
            api::EventType::NodeState,
            api::EventClass::State,
            Some(listener_id),
            Vec::new(),
            "listener_closed",
            Vec::new(),
        );
        encoded_ok(&api::CloseListenerResponse {})
    }

    fn connect(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::ConnectRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(application) = request.application_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(app) = self.applications.get(&application.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if !app.protocols.contains(&request.protocol_id) || request.destination_hint.is_empty() {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        if !self.carrier_instance_running(&self.carrier_handle) {
            return (api::StatusCode::Unavailable as i32, Vec::new());
        }
        let local_endpoint_id = app.endpoint_ids.first().cloned().unwrap_or_default();
        let remote = format!("embedded://{}", hex_encode(&request.destination_hint));
        let transport = match EmbeddedTransport::dial(self.carrier.0.as_ref(), remote) {
            Ok(transport) => transport,
            Err(error) => return (error.status() as i32, Vec::new()),
        };
        if let Some(storage) = self
            .storage
            .as_ref()
            .filter(|_| request.destination_hint.len() == 32)
        {
            let trust = TrustStore::new(storage.store.as_ref(), TrustState::Unknown);
            match trust.effective_trust_state(&request.destination_hint) {
                Ok(TrustState::Unknown) => {
                    if trust
                        .set_state(&request.destination_hint, TrustState::Observed, now_ms())
                        .is_err()
                    {
                        return (api::StatusCode::Internal as i32, Vec::new());
                    }
                }
                Ok(_) => {}
                Err(_) => return (api::StatusCode::Internal as i32, Vec::new()),
            }
        }
        let session_handle = self.next_handle(8);
        let summary = Self::session_summary(
            &session_handle,
            &local_endpoint_id,
            &request.destination_hint,
            &request.protocol_id,
            1,
        );
        self.sessions.insert(
            session_handle.clone(),
            EmbeddedSession {
                application: application.value,
                local_endpoint_id: local_endpoint_id.clone(),
                remote_endpoint_id: request.destination_hint.clone(),
                protocol_id: request.protocol_id.clone(),
                streams: Vec::new(),
                datagrams: VecDeque::new(),
                transport,
                closed: false,
            },
        );
        self.publish_event(
            api::EventType::PathChanged,
            api::EventClass::State,
            Some(session_handle.clone()),
            request.destination_hint.clone(),
            "path_added",
            format!("path 0 carrier {}", self.carrier.0.type_id().0).into_bytes(),
        );
        self.publish_event(
            api::EventType::PathChanged,
            api::EventClass::State,
            Some(session_handle.clone()),
            request.destination_hint.clone(),
            "path_validated",
            b"path 0".to_vec(),
        );
        self.publish_event(
            api::EventType::SessionState,
            api::EventClass::State,
            Some(session_handle.clone()),
            request.destination_hint.clone(),
            "session_active",
            request.protocol_id.as_bytes().to_vec(),
        );
        encoded_ok(&api::ConnectResponse {
            session_handle: Some(api::OpaqueHandle {
                value: session_handle,
            }),
            operation_handle: None,
            session: Some(summary),
        })
    }

    fn accept_incoming_session(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::AcceptIncomingSessionRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let (Some(application), Some(pending)) =
            (request.application_handle, request.pending_session_handle)
        else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(session) = self.sessions.get(&pending.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if session.application != application.value {
            return (api::StatusCode::PermissionDenied as i32, Vec::new());
        }
        let summary = Self::session_summary(
            &pending.value,
            &session.local_endpoint_id,
            &session.remote_endpoint_id,
            &session.protocol_id,
            session.transport.path_count(),
        );
        encoded_ok(&api::AcceptIncomingSessionResponse {
            session_handle: Some(api::OpaqueHandle {
                value: pending.value,
            }),
            session: Some(summary),
        })
    }

    fn migrate_session(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::MigrateSessionRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let (Some(session_handle), Some(carrier_handle)) =
            (request.session_handle, request.carrier_handle)
        else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if carrier_handle.value != self.carrier_handle
            || !self.carrier_instance_running(&carrier_handle.value)
        {
            return (api::StatusCode::FailedPrecondition as i32, Vec::new());
        }
        let (path_id, remote_endpoint_id) = {
            let Some(session) = self.sessions.get_mut(&session_handle.value) else {
                return (api::StatusCode::NotFound as i32, Vec::new());
            };
            let path_id = match session.transport.migrate(
                self.carrier.0.as_ref(),
                request.remote,
                request.keep_old_path,
            ) {
                Ok(path_id) => path_id,
                Err(error) => return (error.status() as i32, Vec::new()),
            };
            (path_id, session.remote_endpoint_id.clone())
        };
        self.publish_event(
            api::EventType::PathChanged,
            api::EventClass::State,
            Some(session_handle.value.clone()),
            remote_endpoint_id,
            "path_migrated",
            path_id.to_be_bytes().to_vec(),
        );
        encoded_ok(&api::MigrateSessionResponse {
            session_handle: Some(session_handle),
            path_id,
            link_handle: None,
        })
    }

    fn reject_incoming_session(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::RejectIncomingSessionRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let (Some(application), Some(pending)) =
            (request.application_handle, request.pending_session_handle)
        else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(session) = self.sessions.get(&pending.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if session.application != application.value {
            return (api::StatusCode::PermissionDenied as i32, Vec::new());
        }
        let session = self
            .sessions
            .remove(&pending.value)
            .expect("session checked above");
        for stream in session.streams {
            self.streams.remove(&stream);
        }
        self.publish_event(
            api::EventType::SessionState,
            api::EventClass::State,
            Some(pending.value),
            session.remote_endpoint_id,
            "session_closed",
            request.reason.into_bytes(),
        );
        encoded_ok(&api::RejectIncomingSessionResponse {})
    }

    fn accept_stream(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::AcceptStreamRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let (Some(application), Some(pending)) =
            (request.application_handle, request.pending_stream_handle)
        else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(stream) = self.streams.get(&pending.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        let Some(session) = self.sessions.get(&stream.session_handle) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if session.application != application.value {
            return (api::StatusCode::PermissionDenied as i32, Vec::new());
        }
        let summary = api::StreamSummary {
            stream_handle: Some(api::OpaqueHandle {
                value: pending.value.clone(),
            }),
            session_handle: Some(api::OpaqueHandle {
                value: stream.session_handle.clone(),
            }),
            stream_id: stream.stream_id,
            state: "open".into(),
            bidirectional: stream.bidirectional,
            ..Default::default()
        };
        encoded_ok(&api::AcceptStreamResponse {
            stream_handle: summary.stream_handle.clone(),
            stream: Some(summary),
        })
    }

    fn reject_stream(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::RejectStreamRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.pending_stream_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(stream) = self.streams.remove(&handle.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if let Some(session) = self.sessions.get_mut(&stream.session_handle) {
            session.streams.retain(|value| value != &handle.value);
        }
        self.publish_event(
            api::EventType::StreamState,
            api::EventClass::State,
            Some(handle.value),
            Vec::new(),
            "stream_reset",
            [
                stream.stream_id.to_be_bytes(),
                request.application_error_code.to_be_bytes(),
            ]
            .concat(),
        );
        encoded_ok(&api::RejectStreamResponse {})
    }

    fn open_stream(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::OpenStreamRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(application) = request.application_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(session_handle) = request.session_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(session) = self.sessions.get(&session_handle.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if session.application != application.value || session.closed {
            return (api::StatusCode::PermissionDenied as i32, Vec::new());
        }
        let stream_handle = self.next_handle(16);
        self.next_stream_id = self.next_stream_id.saturating_add(1);
        let stream_id = self.next_stream_id;
        self.sessions
            .get_mut(&session_handle.value)
            .expect("session checked above")
            .streams
            .push(stream_handle.clone());
        self.streams.insert(
            stream_handle.clone(),
            EmbeddedStream {
                stream_id,
                session_handle: session_handle.value.clone(),
                bidirectional: !request.unidirectional,
                buffer: VecDeque::new(),
                send_closed: false,
                reset: None,
                stopped: false,
                bytes_sent: 0,
                bytes_received: 0,
            },
        );
        self.publish_event(
            api::EventType::StreamState,
            api::EventClass::State,
            Some(stream_handle.clone()),
            Vec::new(),
            "stream_opened",
            Vec::new(),
        );
        let summary = api::StreamSummary {
            stream_handle: Some(api::OpaqueHandle {
                value: stream_handle.clone(),
            }),
            session_handle: Some(session_handle),
            stream_id,
            state: "open".into(),
            bidirectional: !request.unidirectional,
            ..Default::default()
        };
        encoded_ok(&api::OpenStreamResponse {
            stream_handle: Some(api::OpaqueHandle {
                value: stream_handle,
            }),
            stream: Some(summary),
        })
    }

    fn service_transport(&mut self, session_handle: &[u8]) -> Result<(), TransportError> {
        let poll = {
            let Some(session) = self.sessions.get_mut(session_handle) else {
                return Ok(());
            };
            session.transport.poll()?
        };
        self.apply_transport_poll(session_handle, poll);
        Ok(())
    }

    fn apply_transport_poll(&mut self, session_handle: &[u8], poll: TransportPoll) {
        for frame in poll.inbound {
            match frame {
                EmbeddedFrame::Stream {
                    stream_id,
                    fin,
                    data,
                } => {
                    let stream_handle = self.sessions.get(session_handle).and_then(|session| {
                        session.streams.iter().find_map(|handle| {
                            self.streams
                                .get(handle)
                                .filter(|stream| stream.stream_id == stream_id)
                                .map(|_| handle.clone())
                        })
                    });
                    if let Some(stream_handle) = stream_handle {
                        if let Some(stream) = self.streams.get_mut(&stream_handle) {
                            stream.buffer.extend(data);
                            if fin {
                                stream.send_closed = true;
                            }
                        }
                    }
                }
                EmbeddedFrame::Datagram { context_id, data } => {
                    if let Some(session) = self.sessions.get_mut(session_handle) {
                        session.datagrams.push_back(EmbeddedDatagram {
                            context_id,
                            data,
                            expired: false,
                        });
                    }
                }
            }
        }
        for pending in poll.lost {
            match pending {
                PendingDelivery::Stream { stream_id, offset } => {
                    let stream_handle = self.sessions.get(session_handle).and_then(|session| {
                        session.streams.iter().find_map(|handle| {
                            self.streams
                                .get(handle)
                                .filter(|stream| stream.stream_id == stream_id)
                                .map(|_| handle.clone())
                        })
                    });
                    if let Some(stream_handle) = stream_handle {
                        self.publish_event(
                            api::EventType::StreamState,
                            api::EventClass::Edge,
                            Some(stream_handle),
                            Vec::new(),
                            "stream_bytes_lost",
                            [stream_id.to_be_bytes(), offset.to_be_bytes()].concat(),
                        );
                    }
                }
                PendingDelivery::Datagram { context_id } => {
                    self.publish_event(
                        api::EventType::DatagramAvailable,
                        api::EventClass::Edge,
                        Some(session_handle.to_vec()),
                        Vec::new(),
                        "datagram_lost",
                        context_id.to_be_bytes().to_vec(),
                    );
                }
            }
        }
        for event in poll.events {
            self.publish_link_path_event(session_handle, &event);
        }
        if poll.terminal {
            if let Some(session) = self.sessions.get_mut(session_handle) {
                session.closed = true;
            }
            self.publish_event(
                api::EventType::PathChanged,
                api::EventClass::State,
                Some(session_handle.to_vec()),
                Vec::new(),
                "path_failed",
                b"path 0".to_vec(),
            );
            self.publish_event(
                api::EventType::SessionState,
                api::EventClass::State,
                Some(session_handle.to_vec()),
                Vec::new(),
                "session_closed",
                b"transport failure".to_vec(),
            );
        }
    }

    fn publish_link_path_event(&mut self, session_handle: &[u8], event: &LinkEvent) {
        let Some((payload_type, payload)) = (match event {
            LinkEvent::Degraded | LinkEvent::QualityChanged => {
                Some(("path_degraded", b"path 0".to_vec()))
            }
            LinkEvent::AddressRebound => Some((
                "carrier_changed",
                format!("path 0 carrier {}", self.carrier.0.type_id().0).into_bytes(),
            )),
            LinkEvent::MtuChanged { .. } => Some(("path_degraded", b"path 0".to_vec())),
            LinkEvent::Closing => Some(("path_retired", b"path 0".to_vec())),
            LinkEvent::Active | LinkEvent::Writable | LinkEvent::Closed | LinkEvent::Failed => None,
        }) else {
            return;
        };
        self.publish_event(
            api::EventType::PathChanged,
            api::EventClass::State,
            Some(session_handle.to_vec()),
            Vec::new(),
            payload_type,
            payload,
        );
    }

    fn read_stream(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::ReadStreamRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.stream_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let session_handle = match self.streams.get(&handle.value) {
            Some(stream) => stream.session_handle.clone(),
            None => return (api::StatusCode::NotFound as i32, Vec::new()),
        };
        if let Err(error) = self.service_transport(&session_handle) {
            return (error.status() as i32, Vec::new());
        }
        let Some(stream) = self.streams.get_mut(&handle.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if let Some(error_code) = stream.reset {
            return encoded_ok(&api::ReadStreamResponse {
                reset: true,
                application_error_code: error_code,
                ..Default::default()
            });
        }
        if request.maximum_bytes == 0 {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let maximum = usize::try_from(request.maximum_bytes)
            .unwrap_or(usize::MAX)
            .min(256 * 1024);
        let count = maximum.min(stream.buffer.len());
        if count == 0 && request.wait_for_data && !stream.send_closed {
            return (api::StatusCode::Unavailable as i32, Vec::new());
        }
        let data: Vec<u8> = stream.buffer.drain(..count).collect();
        stream.bytes_received = stream
            .bytes_received
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        let eof = stream.send_closed && stream.buffer.is_empty();
        encoded_ok(&api::ReadStreamResponse {
            data,
            eof,
            ..Default::default()
        })
    }

    fn write_stream(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::WriteStreamRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.stream_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if request.data.len() > 256 * 1024 {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let Some(stream) = self.streams.get(&handle.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if stream.reset.is_some() || stream.stopped || stream.send_closed {
            return (api::StatusCode::FailedPrecondition as i32, Vec::new());
        }
        let session_handle = stream.session_handle.clone();
        let stream_number = stream.stream_id;
        let accepted_offset = stream
            .bytes_sent
            .saturating_add(u64::try_from(request.data.len()).unwrap_or(u64::MAX));
        let poll = {
            let Some(session) = self.sessions.get_mut(&session_handle) else {
                return (api::StatusCode::NotFound as i32, Vec::new());
            };
            match session.transport.send(
                encode_stream_frame(stream_number, request.fin, &request.data),
                PendingDelivery::Stream {
                    stream_id: stream_number,
                    offset: accepted_offset,
                },
            ) {
                Ok(poll) => poll,
                Err(error) => return (error.status() as i32, Vec::new()),
            }
        };
        if let Some(stream) = self.streams.get_mut(&handle.value) {
            stream.bytes_sent = accepted_offset;
            if request.fin {
                stream.send_closed = true;
            }
        }
        let accepted_handle = handle.value.clone();
        self.publish_event(
            api::EventType::StreamState,
            api::EventClass::Edge,
            Some(accepted_handle),
            Vec::new(),
            "stream_bytes_accepted",
            [stream_number.to_be_bytes(), accepted_offset.to_be_bytes()].concat(),
        );
        self.apply_transport_poll(&session_handle, poll);
        encoded_ok(&api::WriteStreamResponse {
            accepted_bytes: u32::try_from(request.data.len()).unwrap_or(u32::MAX),
            fin_accepted: request.fin,
        })
    }

    fn close_stream(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::CloseStreamSendRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.stream_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(stream) = self.streams.get_mut(&handle.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        stream.send_closed = true;
        let stream_id = handle.value.clone();
        let _ = stream;
        self.publish_event(
            api::EventType::StreamState,
            api::EventClass::State,
            Some(stream_id),
            Vec::new(),
            "stream_fin",
            Vec::new(),
        );
        encoded_ok(&api::CloseStreamSendResponse {})
    }

    fn reset_stream(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::ResetStreamRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.stream_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(stream) = self.streams.get_mut(&handle.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        stream.reset = Some(request.application_error_code);
        let stream_id = handle.value.clone();
        let stream_number = stream.stream_id;
        let _ = stream;
        self.publish_event(
            api::EventType::StreamState,
            api::EventClass::State,
            Some(stream_id),
            Vec::new(),
            "stream_reset",
            [
                stream_number.to_be_bytes(),
                request.application_error_code.to_be_bytes(),
            ]
            .concat(),
        );
        encoded_ok(&api::ResetStreamResponse {})
    }

    fn stop_stream(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::StopStreamRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.stream_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(stream) = self.streams.get_mut(&handle.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        stream.stopped = true;
        let stream_id = handle.value.clone();
        let stream_number = stream.stream_id;
        let _ = stream;
        self.publish_event(
            api::EventType::StreamState,
            api::EventClass::State,
            Some(stream_id),
            Vec::new(),
            "stream_stopped",
            [
                stream_number.to_be_bytes(),
                request.application_error_code.to_be_bytes(),
            ]
            .concat(),
        );
        encoded_ok(&api::StopStreamResponse {})
    }

    fn send_datagram(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::SendDatagramRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if request.data.len() > 256 * 1024 {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let Some(handle) = request.session_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(session) = self.sessions.get(&handle.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if session.closed {
            return (api::StatusCode::FailedPrecondition as i32, Vec::new());
        }
        let context_id = request.context_id;
        let datagram_data = request.data;
        let datagram_len = datagram_data.len();
        let poll = {
            let Some(session) = self.sessions.get_mut(&handle.value) else {
                return (api::StatusCode::NotFound as i32, Vec::new());
            };
            match session.transport.send(
                encode_datagram_frame(context_id, &datagram_data),
                PendingDelivery::Datagram { context_id },
            ) {
                Ok(poll) => poll,
                Err(error) => return (error.status() as i32, Vec::new()),
            }
        };
        self.next_datagram_id = self.next_datagram_id.saturating_add(1);
        let local_id = self.next_datagram_id;
        let session_id = handle.value.clone();
        self.publish_event(
            api::EventType::DatagramAvailable,
            api::EventClass::Edge,
            Some(session_id.clone()),
            Vec::new(),
            "datagram_queued",
            datagram_len.to_be_bytes().to_vec(),
        );
        self.apply_transport_poll(&session_id, poll);
        encoded_ok(&api::SendDatagramResponse {
            local_datagram_id: local_id,
        })
    }

    fn receive_datagram(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::ReceiveDatagramRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.session_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if request.maximum_bytes == 0 {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        if let Err(error) = self.service_transport(&handle.value) {
            return (error.status() as i32, Vec::new());
        }
        let Some(session) = self.sessions.get_mut(&handle.value) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        let Some(datagram) = session.datagrams.pop_front() else {
            // Match the daemon's empty receive response: no datagram means
            // no session handle. A wait request reports the daemon's
            // `UNAVAILABLE`; a non-waiting poll returns an empty response.
            if request.wait_for_data {
                return (api::StatusCode::Unavailable as i32, Vec::new());
            }
            return encoded_ok(&api::ReceiveDatagramResponse::default());
        };
        if datagram.data.len() > usize::try_from(request.maximum_bytes).unwrap_or(usize::MAX) {
            session.datagrams.push_front(datagram);
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        encoded_ok(&api::ReceiveDatagramResponse {
            session_handle: Some(handle),
            context_id: datagram.context_id,
            data: datagram.data,
            expired: datagram.expired,
        })
    }

    fn close_link(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::CloseLinkRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.link_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if let Some(mut raw) = self.raw_links.remove(&handle.value) {
            if let Err(error) = raw.transport.close(&request.reason) {
                return (error.status() as i32, Vec::new());
            }
            return encoded_ok(&api::CloseLinkResponse {});
        }
        {
            let Some(session) = self.sessions.get_mut(&handle.value) else {
                return (api::StatusCode::NotFound as i32, Vec::new());
            };
            if session.closed {
                return (api::StatusCode::NotFound as i32, Vec::new());
            }
            if let Err(error) = session.transport.close(&request.reason) {
                return (error.status() as i32, Vec::new());
            }
            session.closed = true;
        }
        self.publish_event(
            api::EventType::PathChanged,
            api::EventClass::State,
            Some(handle.value.clone()),
            Vec::new(),
            "path_retired",
            b"path 0".to_vec(),
        );
        self.publish_event(
            api::EventType::SessionState,
            api::EventClass::State,
            Some(handle.value.clone()),
            Vec::new(),
            "session_closing",
            b"clean".to_vec(),
        );
        self.publish_event(
            api::EventType::SessionState,
            api::EventClass::State,
            Some(handle.value),
            Vec::new(),
            "session_closed",
            request.reason.into_bytes(),
        );
        encoded_ok(&api::CloseLinkResponse {})
    }

    fn carrier_instance_summary(
        handle: &[u8],
        instance: &EmbeddedCarrierInstance,
    ) -> api::CarrierInstance {
        api::CarrierInstance {
            carrier_handle: Some(api::OpaqueHandle {
                value: handle.to_vec(),
            }),
            type_id: instance.type_id.clone(),
            label: instance.label.clone(),
            state: instance.state,
            options: instance.options.clone(),
            revision: Some(api::ResourceRevision {
                value: instance.revision,
            }),
            external_plugin: false,
            isolation_state: "in-process".into(),
        }
    }

    fn carrier_handle(&self, handle: Option<&api::OpaqueHandle>) -> Option<Vec<u8>> {
        handle
            .map(|handle| handle.value.clone())
            .or_else(|| Some(self.carrier_handle.clone()))
    }

    fn carrier_instance(
        &self,
        handle: Option<&api::OpaqueHandle>,
    ) -> Option<(Vec<u8>, &EmbeddedCarrierInstance)> {
        let handle = self.carrier_handle(handle)?;
        self.carrier_instances
            .get(&handle)
            .map(|instance| (handle, instance))
    }

    fn carrier_instance_running(&self, handle: &[u8]) -> bool {
        self.carrier_instances
            .get(handle)
            .is_some_and(|instance| instance.state == api::CarrierInstanceState::Running as i32)
    }

    fn list_carrier_types(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        if api::ListCarrierTypesRequest::decode(payload).is_err() {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let capabilities = self.carrier.0.capabilities();
        encoded_ok(&api::ListCarrierTypesResponse {
            types: vec![api::CarrierTypeInfo {
                type_id: capabilities.carrier_type.0,
                display_name: "Embedded carrier".into(),
                built_in: true,
                supports_listen: capabilities.supports_listen,
                supports_dial: capabilities.supports_dial,
                supports_discovery: capabilities.supports_discovery,
                minimum_packet_size: u32::try_from(capabilities.minimum_packet_size)
                    .unwrap_or(u32::MAX),
                maximum_packet_size: u32::try_from(capabilities.maximum_packet_size)
                    .unwrap_or(u32::MAX),
            }],
            page: None,
        })
    }

    fn list_carrier_instances(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        if api::ListCarrierInstancesRequest::decode(payload).is_err() {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let mut instances: Vec<_> = self
            .carrier_instances
            .iter()
            .map(|(handle, instance)| Self::carrier_instance_summary(handle, instance))
            .collect();
        instances.sort_by(|left, right| {
            left.carrier_handle
                .as_ref()
                .map(|handle| &handle.value)
                .cmp(&right.carrier_handle.as_ref().map(|handle| &handle.value))
        });
        encoded_ok(&api::ListCarrierInstancesResponse {
            instances,
            page: None,
        })
    }

    fn get_carrier_instance(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::GetCarrierInstanceRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some((handle, instance)) = self.carrier_instance(request.carrier_handle.as_ref())
        else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        encoded_ok(&api::GetCarrierInstanceResponse {
            instance: Some(Self::carrier_instance_summary(&handle, instance)),
        })
    }

    fn create_carrier_instance(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::CreateCarrierInstanceRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let carrier_type = self.carrier.0.type_id().0;
        if request.label.trim().is_empty() {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        if request.type_id != carrier_type {
            return (api::StatusCode::NotFound as i32, Vec::new());
        }
        if request
            .options
            .iter()
            .any(|mutation| mutation.key.trim().is_empty() || mutation.operation.is_none())
        {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        let mut options = Vec::new();
        for mutation in request.options {
            match mutation.operation {
                Some(api::config_mutation::Operation::SetValue(value)) => {
                    options.push(api::ConfigEntry {
                        key: mutation.key,
                        value,
                        sensitive_present: false,
                    });
                }
                Some(api::config_mutation::Operation::SetSecret(_)) => {
                    options.push(api::ConfigEntry {
                        key: mutation.key,
                        value: String::new(),
                        sensitive_present: true,
                    });
                }
                Some(api::config_mutation::Operation::Clear(_)) | None => {
                    options.retain(|option: &api::ConfigEntry| option.key != mutation.key);
                }
            }
        }
        let handle = self.next_handle(16);
        let instance = EmbeddedCarrierInstance {
            type_id: carrier_type,
            label: request.label,
            state: if request.enabled {
                api::CarrierInstanceState::Created as i32
            } else {
                api::CarrierInstanceState::Disabled as i32
            },
            options,
            revision: 1,
        };
        let summary = Self::carrier_instance_summary(&handle, &instance);
        self.carrier_instances.insert(handle, instance);
        encoded_ok(&api::CreateCarrierInstanceResponse {
            instance: Some(summary),
        })
    }

    fn update_carrier_instance(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::UpdateCarrierInstanceRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.carrier_handle.map(|handle| handle.value) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(instance) = self.carrier_instances.get_mut(&handle) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if request
            .expected_revision
            .is_some_and(|revision| revision.value != instance.revision)
        {
            return (api::StatusCode::Conflict as i32, Vec::new());
        }
        for mutation in request.options {
            if mutation.key.trim().is_empty() {
                return (api::StatusCode::InvalidArgument as i32, Vec::new());
            }
            match mutation.operation {
                Some(api::config_mutation::Operation::SetValue(value)) => {
                    if let Some(option) = instance
                        .options
                        .iter_mut()
                        .find(|option| option.key == mutation.key)
                    {
                        option.value = value;
                    } else {
                        instance.options.push(api::ConfigEntry {
                            key: mutation.key,
                            value,
                            sensitive_present: false,
                        });
                    }
                }
                Some(api::config_mutation::Operation::Clear(_)) => {
                    instance.options.retain(|option| option.key != mutation.key);
                }
                Some(api::config_mutation::Operation::SetSecret(_)) => {
                    if let Some(option) = instance
                        .options
                        .iter_mut()
                        .find(|option| option.key == mutation.key)
                    {
                        option.value.clear();
                        option.sensitive_present = true;
                    } else {
                        instance.options.push(api::ConfigEntry {
                            key: mutation.key,
                            value: String::new(),
                            sensitive_present: true,
                        });
                    }
                }
                None => return (api::StatusCode::InvalidArgument as i32, Vec::new()),
            }
        }
        instance.revision = instance.revision.saturating_add(1);
        let summary = Self::carrier_instance_summary(&handle, instance);
        encoded_ok(&api::UpdateCarrierInstanceResponse {
            instance: Some(summary),
            effects: Vec::new(),
        })
    }

    fn start_carrier(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::StartCarrierRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.carrier_handle.map(|handle| handle.value) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(instance) = self.carrier_instances.get_mut(&handle) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if instance.state == api::CarrierInstanceState::Disabled as i32 {
            return (api::StatusCode::FailedPrecondition as i32, Vec::new());
        }
        instance.state = api::CarrierInstanceState::Running as i32;
        instance.revision = instance.revision.saturating_add(1);
        let summary = Self::carrier_instance_summary(&handle, instance);
        encoded_ok(&api::StartCarrierResponse {
            instance: Some(summary),
        })
    }

    fn stop_carrier(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::StopCarrierRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.carrier_handle.map(|handle| handle.value) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if !self.carrier_instances.contains_key(&handle) {
            return (api::StatusCode::NotFound as i32, Vec::new());
        }
        let sessions: Vec<Vec<u8>> = self.sessions.keys().cloned().collect();
        for session_handle in sessions {
            let should_close = self
                .sessions
                .get(&session_handle)
                .is_some_and(|session| !session.closed);
            if !should_close {
                continue;
            }
            if let Some(session) = self.sessions.get_mut(&session_handle) {
                let _ = session.transport.close("carrier stopped");
                session.closed = true;
            }
            self.publish_event(
                api::EventType::PathChanged,
                api::EventClass::State,
                Some(session_handle.clone()),
                Vec::new(),
                "path_retired",
                b"path 0".to_vec(),
            );
            self.publish_event(
                api::EventType::SessionState,
                api::EventClass::State,
                Some(session_handle),
                Vec::new(),
                "session_closing",
                b"clean".to_vec(),
            );
        }
        if !request.drain_links {
            let raw_handles: Vec<Vec<u8>> = self
                .raw_links
                .iter()
                .filter(|(_, link)| link.carrier_handle == handle)
                .map(|(link_handle, _)| link_handle.clone())
                .collect();
            for raw_handle in raw_handles {
                if let Some(mut raw) = self.raw_links.remove(&raw_handle) {
                    let _ = raw.transport.close("carrier stopped");
                }
            }
        }
        let instance = self
            .carrier_instances
            .get_mut(&handle)
            .expect("checked carrier instance");
        instance.state = api::CarrierInstanceState::Stopped as i32;
        instance.revision = instance.revision.saturating_add(1);
        let summary = Self::carrier_instance_summary(&handle, instance);
        encoded_ok(&api::StopCarrierResponse {
            instance: Some(summary),
        })
    }

    fn delete_carrier_instance(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::DeleteCarrierInstanceRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.carrier_handle.map(|handle| handle.value) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if !self.carrier_instances.contains_key(&handle) {
            return (api::StatusCode::NotFound as i32, Vec::new());
        }
        if self.sessions.values().any(|session| !session.closed) {
            return (api::StatusCode::FailedPrecondition as i32, Vec::new());
        }
        if self
            .raw_links
            .values()
            .any(|link| link.carrier_handle == handle)
        {
            return (api::StatusCode::FailedPrecondition as i32, Vec::new());
        }
        self.carrier_instances.remove(&handle);
        encoded_ok(&api::DeleteCarrierInstanceResponse {})
    }

    fn dial_carrier(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::DialRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.carrier_handle.map(|handle| handle.value) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if request.remote.trim().is_empty() {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        }
        if !self.carrier_instance_running(&handle) {
            return if self.carrier_instances.contains_key(&handle) {
                (api::StatusCode::FailedPrecondition as i32, Vec::new())
            } else {
                (api::StatusCode::NotFound as i32, Vec::new())
            };
        }
        let transport = match EmbeddedTransport::dial(self.carrier.0.as_ref(), request.remote) {
            Ok(transport) => transport,
            Err(error) => return (error.status() as i32, Vec::new()),
        };
        let link_handle = self.next_handle(16);
        let properties = transport.properties();
        self.raw_links.insert(
            link_handle.clone(),
            EmbeddedRawLink {
                carrier_handle: handle.clone(),
                transport,
            },
        );
        encoded_ok(&api::DialResponse {
            link: Some(api::LinkSummary {
                link_handle: Some(api::OpaqueHandle { value: link_handle }),
                carrier_handle: Some(api::OpaqueHandle { value: handle }),
                carrier_type_id: self.carrier.0.type_id().0,
                state: "active".into(),
                current_mtu: u32::try_from(properties.current_mtu).unwrap_or(u32::MAX),
                bytes_sent: 0,
                bytes_received: 0,
                scope: "carrier".into(),
            }),
        })
    }

    fn list_links(&self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::ListLinksRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(carrier_handle) = self.carrier_handle(request.carrier_handle.as_ref()) else {
            return (api::StatusCode::NotFound as i32, Vec::new());
        };
        if !self.carrier_instances.contains_key(&carrier_handle) {
            return (api::StatusCode::NotFound as i32, Vec::new());
        }
        let mut links: Vec<_> = self
            .sessions
            .iter()
            .filter(|_| carrier_handle == self.carrier_handle)
            .map(|(handle, session)| {
                let properties = session.transport.properties();
                api::LinkSummary {
                    link_handle: Some(api::OpaqueHandle {
                        value: handle.clone(),
                    }),
                    carrier_handle: Some(api::OpaqueHandle {
                        value: carrier_handle.clone(),
                    }),
                    carrier_type_id: self.carrier.0.type_id().0.clone(),
                    state: if session.closed { "closed" } else { "active" }.into(),
                    current_mtu: u32::try_from(properties.current_mtu).unwrap_or(u32::MAX),
                    bytes_sent: 0,
                    bytes_received: 0,
                    scope: "process".into(),
                }
            })
            .collect();
        links.extend(self.raw_links.iter().filter_map(|(handle, raw)| {
            if raw.carrier_handle != carrier_handle {
                return None;
            }
            let properties = raw.transport.properties();
            Some(api::LinkSummary {
                link_handle: Some(api::OpaqueHandle {
                    value: handle.clone(),
                }),
                carrier_handle: Some(api::OpaqueHandle {
                    value: carrier_handle.clone(),
                }),
                carrier_type_id: self.carrier.0.type_id().0.clone(),
                state: "active".into(),
                current_mtu: u32::try_from(properties.current_mtu).unwrap_or(u32::MAX),
                bytes_sent: 0,
                bytes_received: 0,
                scope: "carrier".into(),
            })
        }));
        links.sort_by(|left, right| {
            left.link_handle
                .as_ref()
                .map(|handle| &handle.value)
                .cmp(&right.link_handle.as_ref().map(|handle| &handle.value))
        });
        encoded_ok(&api::ListLinksResponse { links, page: None })
    }

    fn subscribe_events(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::SubscribeRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let filter = request.filter.unwrap_or_default();
        let filter_digest = event_filter_digest(&filter);
        let now = now_ms();
        let resume_sequence = if request.resume_cursor.is_empty() {
            None
        } else {
            let Some(cursor) =
                EventResumeCursor::decode(&request.resume_cursor, &self.event_cursor_key)
            else {
                return Self::event_cursor_out_of_range();
            };
            if !cursor.validate(0, self.cursor_generation(), filter_digest, now) {
                return Self::event_cursor_out_of_range();
            }
            Some(cursor.sequence())
        };
        let history = match resume_sequence {
            Some(sequence) => match self.history_after(sequence) {
                Ok(history) => history,
                Err(()) => return Self::event_cursor_out_of_range(),
            },
            None if filter.include_initial_snapshot => self.event_history.iter().cloned().collect(),
            None => Vec::new(),
        };
        let handle = self.next_handle(8);
        self.subscriptions.insert(
            handle.clone(),
            EmbeddedSubscription {
                filter: filter.clone(),
                next_sequence: 1,
                queue: VecDeque::new(),
                queue_bytes: 0,
                in_flight: VecDeque::new(),
                in_flight_bytes: 0,
                out_of_sync_from: None,
                out_of_sync_to: None,
            },
        );
        for (journal_sequence, event) in history {
            self.enqueue_event_with_journal(&handle, event, journal_sequence);
        }
        encoded_ok(&api::SubscribeResponse {
            subscription_handle: Some(api::OpaqueHandle {
                value: handle.clone(),
            }),
            resume_cursor: self.make_event_cursor(filter_digest, self.event_history_next_sequence),
            first_event_sequence: 1,
        })
    }

    fn event_cursor_out_of_range() -> (i32, Vec<u8>) {
        (
            api::StatusCode::OutOfRange as i32,
            api::EventGap {
                snapshot_required: true,
                ..Default::default()
            }
            .encode_to_vec(),
        )
    }

    fn cursor_generation(&self) -> [u8; 16] {
        let mut generation = [0u8; 16];
        generation[8..].copy_from_slice(&self.generation.to_be_bytes());
        generation
    }

    fn make_event_cursor(&self, filter_digest: [u8; 16], sequence: u64) -> Vec<u8> {
        EventResumeCursor::encode(
            0,
            self.cursor_generation(),
            filter_digest,
            sequence,
            now_ms().saturating_add(EVENT_CURSOR_TTL_MS),
            &self.event_cursor_key,
        )
    }

    fn history_after(&self, after_sequence: u64) -> Result<Vec<(u64, api::Event)>, ()> {
        if after_sequence > self.event_history_next_sequence {
            return Err(());
        }
        if self.event_history.is_empty() && after_sequence < self.event_history_next_sequence {
            return Err(());
        }
        if let Some((oldest, _)) = self.event_history.front() {
            if after_sequence.saturating_add(1) < *oldest {
                return Err(());
            }
        }
        Ok(self
            .event_history
            .iter()
            .filter(|(sequence, _)| *sequence > after_sequence)
            .cloned()
            .collect())
    }

    fn unsubscribe_events(&mut self, payload: &[u8]) -> (i32, Vec<u8>) {
        let Ok(request) = api::UnsubscribeRequest::decode(payload) else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        let Some(handle) = request.subscription_handle else {
            return (api::StatusCode::InvalidArgument as i32, Vec::new());
        };
        if self.subscriptions.remove(&handle.value).is_none() {
            return (api::StatusCode::NotFound as i32, Vec::new());
        }
        encoded_ok(&api::UnsubscribeResponse {})
    }

    pub(crate) fn next_event(&mut self, subscription: &[u8]) -> Result<Event, ClientError> {
        let filter_digest = self
            .subscriptions
            .get(subscription)
            .map(|state| event_filter_digest(&state.filter))
            .ok_or(ClientError::NotFound)?;
        let current_cursor =
            self.make_event_cursor(filter_digest, self.event_history_next_sequence);
        let Some(subscription_state) = self.subscriptions.get_mut(subscription) else {
            return Err(ClientError::NotFound);
        };
        if let Some(first_missing_sequence) = subscription_state.out_of_sync_from.take() {
            let last_missing_sequence = subscription_state
                .out_of_sync_to
                .take()
                .unwrap_or(first_missing_sequence);
            let event = api::Event {
                subscription_handle: Some(api::OpaqueHandle {
                    value: subscription.to_vec(),
                }),
                event_sequence: first_missing_sequence,
                event_type: api::EventType::EventGap as i32,
                event_class: api::EventClass::Critical as i32,
                occurred_at_unix_ms: now_unix_ms(),
                payload_type: "event_gap".into(),
                payload: api::EventGap {
                    first_missing_sequence,
                    last_missing_sequence,
                    snapshot_required: true,
                }
                .encode_to_vec(),
                resume_cursor: current_cursor,
                ..Default::default()
            };
            return Event::from_proto(event, self.generation);
        }
        let Some(event) = subscription_state.queue.pop_front() else {
            return Err(ClientError::WouldBlock);
        };
        let event_sequence = event.event_sequence;
        subscription_state.queue_bytes = subscription_state
            .queue_bytes
            .saturating_sub(event.payload.len());
        subscription_state
            .in_flight
            .push_back((event_sequence, event.payload.len()));
        subscription_state.in_flight_bytes = subscription_state
            .in_flight_bytes
            .saturating_add(event.payload.len());
        Event::from_proto(event, self.generation)
    }

    pub(crate) fn acknowledge_event(
        &mut self,
        subscription: &[u8],
        highest_contiguous_sequence: u64,
    ) -> Result<(), ClientError> {
        let Some(subscription_state) = self.subscriptions.get_mut(subscription) else {
            return Err(ClientError::NotFound);
        };
        while subscription_state
            .in_flight
            .front()
            .is_some_and(|(sequence, _)| *sequence <= highest_contiguous_sequence)
        {
            if let Some((_sequence, payload_len)) = subscription_state.in_flight.pop_front() {
                subscription_state.in_flight_bytes = subscription_state
                    .in_flight_bytes
                    .saturating_sub(payload_len);
            }
        }
        Ok(())
    }

    fn publish_event(
        &mut self,
        event_type: api::EventType,
        event_class: api::EventClass,
        resource_handle: Option<Vec<u8>>,
        resource_id: Vec<u8>,
        payload_type: &str,
        payload: Vec<u8>,
    ) {
        let event = api::Event {
            event_type: event_type as i32,
            event_class: event_class as i32,
            occurred_at_unix_ms: now_unix_ms(),
            resource_handle: resource_handle.map(|value| api::OpaqueHandle { value }),
            resource_id,
            payload_type: payload_type.to_string(),
            payload,
            ..Default::default()
        };
        self.event_history_next_sequence = self.event_history_next_sequence.saturating_add(1);
        let journal_sequence = self.event_history_next_sequence;
        self.event_history_bytes = self.event_history_bytes.saturating_add(event.payload.len());
        self.event_history
            .push_back((journal_sequence, event.clone()));
        while self.event_history.len() > 100
            || self.event_history_bytes > EMBEDDED_EVENT_MAX_BACKLOG_BYTES
        {
            if let Some((_, old_event)) = self.event_history.pop_front() {
                self.event_history_bytes = self
                    .event_history_bytes
                    .saturating_sub(old_event.payload.len());
            } else {
                break;
            }
        }
        let handles: Vec<Vec<u8>> = self.subscriptions.keys().cloned().collect();
        for handle in handles {
            self.enqueue_event_with_journal(&handle, event.clone(), journal_sequence);
        }
    }

    fn enqueue_event_with_journal(
        &mut self,
        subscription: &[u8],
        mut event: api::Event,
        journal_sequence: u64,
    ) {
        let Some(filter_digest) = self
            .subscriptions
            .get(subscription)
            .map(|state| event_filter_digest(&state.filter))
        else {
            return;
        };
        let cursor_sequence = if journal_sequence == 0 {
            self.event_history_next_sequence
        } else {
            journal_sequence
        };
        let resume_cursor = self.make_event_cursor(filter_digest, cursor_sequence);
        let Some(subscription_state) = self.subscriptions.get_mut(subscription) else {
            return;
        };
        if !event_matches_filter(&event, &subscription_state.filter) {
            return;
        }
        let sequence = subscription_state.next_sequence;
        subscription_state.next_sequence = subscription_state.next_sequence.saturating_add(1);
        if subscription_state.queue.len() + subscription_state.in_flight.len()
            >= EMBEDDED_EVENT_MAX_BACKLOG
            || subscription_state
                .queue_bytes
                .saturating_add(subscription_state.in_flight_bytes)
                .saturating_add(event.payload.len())
                > EMBEDDED_EVENT_MAX_BACKLOG_BYTES
        {
            // SAMPLE events may drop under pressure. Stateful events remain
            // represented by an explicit gap, never by silently evicting the
            // oldest lifecycle record.
            if event.event_class == api::EventClass::Sample as i32 {
                return;
            }
            subscription_state.out_of_sync_from.get_or_insert(sequence);
            subscription_state.out_of_sync_to = Some(sequence);
            return;
        }
        event.subscription_handle = Some(api::OpaqueHandle {
            value: subscription.to_vec(),
        });
        event.event_sequence = sequence;
        event.resume_cursor = resume_cursor;
        subscription_state.queue_bytes += event.payload.len();
        subscription_state.queue.push_back(event);
    }

    fn session_summary(
        handle: &[u8],
        local_endpoint_id: &[u8],
        remote_endpoint_id: &[u8],
        protocol_id: &str,
        active_paths: usize,
    ) -> api::SessionSummary {
        api::SessionSummary {
            session_handle: Some(api::OpaqueHandle {
                value: handle.to_vec(),
            }),
            local_endpoint_id: local_endpoint_id.to_vec(),
            remote_endpoint_id: remote_endpoint_id.to_vec(),
            state: api::SessionState::Active as i32,
            protocol_id: protocol_id.to_string(),
            active_paths: u32::try_from(active_paths).unwrap_or(u32::MAX),
            created_at_unix_ms: now_unix_ms(),
            last_activity_unix_ms: now_unix_ms(),
            application_owned: true,
            ..Default::default()
        }
    }

    fn next_handle(&mut self, width: usize) -> Vec<u8> {
        self.next_handle = self.next_handle.saturating_add(1);
        Self::handle_for_counter(self.next_handle, width)
    }

    fn peek_next_handle(&self, width: usize) -> Vec<u8> {
        Self::handle_for_counter(self.next_handle.saturating_add(1), width)
    }

    fn handle_for_counter(counter: u64, width: usize) -> Vec<u8> {
        let value = counter.to_be_bytes();
        if width <= value.len() {
            value[value.len() - width..].to_vec()
        } else {
            let mut handle = vec![0u8; width];
            handle[width - value.len()..].copy_from_slice(&value);
            handle
        }
    }
}

fn event_matches_filter(event: &api::Event, filter: &api::EventFilter) -> bool {
    if !filter.event_types.is_empty() && !filter.event_types.contains(&event.event_type) {
        return false;
    }
    if !filter.resource_handles.is_empty() {
        let Some(resource) = event.resource_handle.as_ref() else {
            return false;
        };
        if !filter
            .resource_handles
            .iter()
            .any(|handle| handle.value == resource.value)
        {
            return false;
        }
    }
    if !filter.endpoint_ids.is_empty() && !filter.endpoint_ids.contains(&event.resource_id) {
        return false;
    }
    let event_severity = match api::EventClass::try_from(event.event_class)
        .unwrap_or(api::EventClass::Unspecified)
    {
        api::EventClass::Critical => api::DiagnosticSeverity::Critical as i32,
        api::EventClass::State => api::DiagnosticSeverity::Warning as i32,
        api::EventClass::Edge | api::EventClass::Sample | api::EventClass::Unspecified => {
            api::DiagnosticSeverity::Info as i32
        }
    };
    filter.minimum_severity == 0 || event_severity >= filter.minimum_severity
}

fn encoded_ok<M: Message>(message: &M) -> (i32, Vec<u8>) {
    let mut payload = Vec::new();
    if message.encode(&mut payload).is_err() {
        return (api::StatusCode::Internal as i32, Vec::new());
    }
    (api::StatusCode::Ok as i32, payload)
}

fn identity_seeds(identity: &NodeIdentity) -> Vec<u8> {
    let mut seeds = Vec::with_capacity(64);
    seeds.extend_from_slice(&identity.identity.to_seed());
    seeds.extend_from_slice(&identity.static_handshake.to_seed());
    seeds
}

fn identity_from_seeds(seeds: &[u8], context: &str) -> Result<NodeIdentity, String> {
    if seeds.len() != 64 {
        return Err(format!("{context} has malformed seed record"));
    }
    let identity_seed: [u8; 32] = seeds[..32]
        .try_into()
        .map_err(|_| format!("{context} identity seed is malformed"))?;
    let static_seed: [u8; 32] = seeds[32..]
        .try_into()
        .map_err(|_| format!("{context} static seed is malformed"))?;
    Ok(NodeIdentity {
        identity: IdentityKeyPair::from_seed(identity_seed),
        static_handshake: StaticHandshakeKeyPair::from_seed(static_seed),
    })
}

fn endpoint_metadata_key(endpoint_id: &[u8]) -> Vec<u8> {
    let mut key = b"endpoint/".to_vec();
    key.extend_from_slice(endpoint_id);
    key
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn encode_endpoint_metadata(kind: i32, label: &str) -> Result<Vec<u8>, String> {
    let label = label.as_bytes();
    let length =
        u16::try_from(label.len()).map_err(|_| "embedded endpoint label too long".to_string())?;
    let mut value = Vec::with_capacity(6 + label.len());
    value.extend_from_slice(&kind.to_be_bytes());
    value.extend_from_slice(&length.to_be_bytes());
    value.extend_from_slice(label);
    Ok(value)
}

fn decode_endpoint_metadata(value: &[u8]) -> Result<(i32, String), String> {
    if value.len() < 6 {
        return Err("embedded endpoint metadata is truncated".into());
    }
    let kind = i32::from_be_bytes(
        value[..4]
            .try_into()
            .map_err(|_| "embedded endpoint kind is malformed".to_string())?,
    );
    let length =
        usize::from(u16::from_be_bytes(value[4..6].try_into().map_err(
            |_| "embedded endpoint label length is malformed".to_string(),
        )?));
    let label = value
        .get(6..6 + length)
        .ok_or_else(|| "embedded endpoint label is truncated".to_string())?;
    if value.len() != 6 + length {
        return Err("embedded endpoint metadata has trailing bytes".into());
    }
    let label = std::str::from_utf8(label)
        .map_err(|_| "embedded endpoint label is not utf-8".to_string())?
        .to_string();
    Ok((kind, label))
}

fn generation_for(endpoint_id: &[u8]) -> u64 {
    let mut value = 0xcbf2_9ce4_8422_2325u64;
    for byte in endpoint_id {
        value ^= u64::from(*byte);
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if value == 0 {
        1
    } else {
        value
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

fn now_unix_ms() -> i64 {
    i64::try_from(now_ms()).unwrap_or(i64::MAX)
}

#[derive(Debug)]
struct EmbeddedClock;

impl Clock for EmbeddedClock {
    fn now(&self) -> Instant {
        Instant(now_ms())
    }
}

#[derive(Debug)]
struct EmbeddedEntropy;

impl EntropySource for EmbeddedEntropy {
    fn fill(&self, out: &mut [u8]) {
        rand_core::OsRng.fill_bytes(out);
    }
}

#[cfg(test)]
mod tests {
    use crate::client::ClientError;
    use crate::policy::Policy;
    use prost::Message;
    use umc_control::proto::umc::api::v1 as api;
    use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};

    #[test]
    fn embedded_event_backlog_stays_charged_until_ack_and_reports_state_gap() {
        let config = super::EmbeddedConfig::default();
        let mut backend = super::EmbeddedBackend::new(&config).expect("embedded backend");
        let (status, payload) = backend.request_raw(
            "EventService",
            "Subscribe",
            &api::SubscribeRequest::default().encode_to_vec(),
            None,
        );
        assert_eq!(status, api::StatusCode::Ok as i32);
        let subscription = api::SubscribeResponse::decode(payload.as_slice())
            .expect("subscribe response")
            .subscription_handle
            .expect("subscription handle")
            .value;

        for _ in 0..1_024 {
            backend.publish_event(
                api::EventType::NodeState,
                api::EventClass::State,
                None,
                Vec::new(),
                "state",
                vec![1],
            );
        }
        for _ in 0..1_024 {
            backend.next_event(&subscription).expect("queued event");
        }
        backend.publish_event(
            api::EventType::NodeState,
            api::EventClass::State,
            None,
            Vec::new(),
            "overflow",
            vec![2],
        );
        let gap = backend.next_event(&subscription).expect("event gap");
        assert_eq!(gap.event_type(), api::EventType::EventGap);

        backend
            .acknowledge_event(&subscription, 1_024)
            .expect("acknowledge in-flight events");
        backend.publish_event(
            api::EventType::NodeState,
            api::EventClass::State,
            None,
            Vec::new(),
            "after_ack",
            vec![3],
        );
        assert_eq!(
            backend
                .next_event(&subscription)
                .expect("post-ack event")
                .payload(),
            &[3]
        );
    }

    #[test]
    fn embedded_event_resume_cursor_replays_only_events_after_cursor() {
        let config = super::EmbeddedConfig::default();
        let mut backend = super::EmbeddedBackend::new(&config).expect("embedded backend");
        let subscribe = api::SubscribeRequest::default().encode_to_vec();
        let (_, payload) = backend.request_raw("EventService", "Subscribe", &subscribe, None);
        let first = api::SubscribeResponse::decode(payload.as_slice()).expect("subscribe");
        let first_handle = first
            .subscription_handle
            .as_ref()
            .expect("first handle")
            .value
            .clone();

        backend.publish_event(
            api::EventType::NodeState,
            api::EventClass::State,
            None,
            Vec::new(),
            "first",
            vec![1],
        );
        let delivered = backend.next_event(&first_handle).expect("first event");
        let cursor = delivered.resume_cursor().to_vec();
        let unsubscribe = api::UnsubscribeRequest {
            subscription_handle: Some(api::OpaqueHandle {
                value: first_handle,
            }),
        }
        .encode_to_vec();
        let (status, _) = backend.request_raw("EventService", "Unsubscribe", &unsubscribe, None);
        assert_eq!(status, api::StatusCode::Ok as i32);

        let resumed = api::SubscribeRequest {
            filter: None,
            resume_cursor: cursor,
        }
        .encode_to_vec();
        let (status, payload) = backend.request_raw("EventService", "Subscribe", &resumed, None);
        assert_eq!(status, api::StatusCode::Ok as i32);
        let resumed_handle = api::SubscribeResponse::decode(payload.as_slice())
            .expect("resumed subscribe")
            .subscription_handle
            .expect("resumed handle")
            .value;
        assert!(matches!(
            backend.next_event(&resumed_handle),
            Err(ClientError::WouldBlock)
        ));

        backend.publish_event(
            api::EventType::NodeState,
            api::EventClass::State,
            None,
            Vec::new(),
            "second",
            vec![2],
        );
        let next = backend.next_event(&resumed_handle).expect("second event");
        assert_eq!(next.payload_type(), "second");
        assert_eq!(
            next.sequence(),
            1,
            "a resumed subscription has its own sequence"
        );
    }

    #[test]
    fn embedded_deadline_validation_matches_daemon_request_boundary() {
        let config = super::EmbeddedConfig::default();
        let mut backend = super::EmbeddedBackend::new(&config).expect("embedded backend");
        let (status, _) = backend.request_raw(
            "IdentityService",
            "ListIdentities",
            &api::ListIdentitiesRequest::default().encode_to_vec(),
            Some(-1),
        );
        assert_eq!(status, api::StatusCode::InvalidArgument as i32);
        let (status, _) = backend.request_raw(
            "IdentityService",
            "ListIdentities",
            &api::ListIdentitiesRequest::default().encode_to_vec(),
            Some(1),
        );
        assert_eq!(status, api::StatusCode::DeadlineExceeded as i32);
    }

    #[tokio::test]
    async fn embedded_event_wait_honors_future_deadline_instead_of_would_blocking() {
        let mut client = crate::Client::embedded();
        let subscription = client
            .subscribe_events(crate::EventFilter {
                event_types: vec![api::EventType::PathChanged],
                ..Default::default()
            })
            .await
            .expect("subscription");
        let deadline = super::now_unix_ms().saturating_add(10);
        assert!(matches!(
            client
                .next_event_with_deadline(&subscription, Some(deadline))
                .await,
            Err(ClientError::DeadlineExceeded)
        ));
    }

    #[tokio::test]
    async fn embedded_stream_wait_honors_operation_deadline() {
        let mut client = crate::Client::embedded();
        let endpoint = client.load_endpoint("default").await.expect("endpoint");
        let application = client
            .register_application(
                "read-deadline-test",
                [18u8; 16],
                &[endpoint.endpoint_id()],
                &["org.example.read/1"],
            )
            .await
            .expect("application");
        let session = client
            .connect_session(
                &application,
                b"read-deadline-peer",
                "org.example.read/1",
                &Policy::default(),
            )
            .await
            .expect("session");
        let stream = client
            .open_stream(&application, &session, false)
            .await
            .expect("stream");
        let deadline = super::now_unix_ms().saturating_add(10);
        assert!(matches!(
            client
                .read_stream_with_deadline(&stream, 64, true, Some(deadline))
                .await,
            Err(ClientError::DeadlineExceeded)
        ));
    }

    #[tokio::test]
    async fn embedded_datagram_wait_honors_operation_deadline() {
        let mut client = crate::Client::embedded();
        let endpoint = client.load_endpoint("default").await.expect("endpoint");
        let application = client
            .register_application(
                "datagram-deadline-test",
                [19u8; 16],
                &[endpoint.endpoint_id()],
                &["org.example.datagram/1"],
            )
            .await
            .expect("application");
        let session = client
            .connect_session(
                &application,
                b"datagram-deadline-peer",
                "org.example.datagram/1",
                &Policy::default(),
            )
            .await
            .expect("session");
        let deadline = super::now_unix_ms().saturating_add(10);
        assert!(matches!(
            client
                .receive_datagram_with_deadline(&application, &session, 64, true, Some(deadline),)
                .await,
            Err(ClientError::DeadlineExceeded)
        ));
    }

    #[tokio::test]
    async fn embedded_backend_imports_passphrase_identity() {
        let identity = IdentityKeyPair::from_seed([17u8; 32]);
        let static_handshake = StaticHandshakeKeyPair::from_seed([23u8; 32]);
        let mut seeds = Vec::with_capacity(64);
        seeds.extend_from_slice(&identity.to_seed());
        seeds.extend_from_slice(&static_handshake.to_seed());
        let encrypted =
            umc_storage::secret_export::seal(b"test-passphrase", &seeds).expect("identity export");
        let expected_endpoint = umc_core::node::NodeIdentity {
            identity: identity.clone(),
            static_handshake: static_handshake.clone(),
        }
        .endpoint_id();

        let mut client = crate::Client::embedded();
        let imported = client
            .import_endpoint(&encrypted, b"test-passphrase", "")
            .await
            .expect("embedded import");
        assert_eq!(imported.endpoint_id(), expected_endpoint.as_slice());
        assert!(imported.secret_available());
    }

    #[tokio::test]
    async fn embedded_backend_rejects_wrong_passphrase_and_ambiguous_keychain_reference() {
        let identity = IdentityKeyPair::from_seed([31u8; 32]);
        let static_handshake = StaticHandshakeKeyPair::from_seed([37u8; 32]);
        let mut seeds = Vec::with_capacity(64);
        seeds.extend_from_slice(&identity.to_seed());
        seeds.extend_from_slice(&static_handshake.to_seed());
        let encrypted =
            umc_storage::secret_export::seal(b"right-passphrase", &seeds).expect("identity export");

        let mut client = crate::Client::embedded();
        assert!(matches!(
            client
                .import_endpoint(&encrypted, b"wrong-passphrase", "")
                .await,
            Err(ClientError::PermissionDenied)
        ));
        assert!(matches!(
            client
                .import_endpoint(&encrypted, b"right-passphrase", "os-keychain:item")
                .await,
            Err(ClientError::InvalidArgument)
        ));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn embedded_backend_round_trips_streams_and_datagrams() {
        let mut client = crate::Client::embedded();
        assert!(client.is_embedded());
        let endpoint = client.load_endpoint("default").await.expect("endpoint");
        let subscription = client
            .subscribe_events(crate::EventFilter::default())
            .await
            .expect("subscription");
        let application = client
            .register_application(
                "embedded-test",
                [7u8; 16],
                &[endpoint.endpoint_id()],
                &["org.example.echo/1"],
            )
            .await
            .expect("application");
        let event = client.next_event(&subscription).await.expect("event");
        assert_eq!(
            event.event_type(),
            umc_control::proto::umc::api::v1::EventType::NodeState
        );
        client
            .acknowledge_event(&subscription, event.sequence())
            .await
            .expect("ack event");
        let listener = client
            .listen(
                &application,
                endpoint.endpoint_id(),
                "org.example.echo/1",
                &Policy::default(),
            )
            .await
            .expect("listener");
        let session = client
            .connect_session(
                &application,
                b"embedded-peer",
                "org.example.echo/1",
                &Policy::default(),
            )
            .await
            .expect("session");
        assert_eq!(
            client
                .accept_session(&application, &session)
                .await
                .expect("accept loopback session")
                .as_bytes(),
            session.as_bytes()
        );
        assert!(matches!(
            client
                .receive_datagram(&application, &session, 64, false)
                .await,
            Err(ClientError::WouldBlock)
        ));
        assert!(matches!(
            client
                .receive_datagram(&application, &session, 0, false)
                .await,
            Err(ClientError::InvalidArgument)
        ));
        let stream = client
            .open_stream(&application, &session, false)
            .await
            .expect("stream");
        assert!(matches!(
            client.read_stream(&stream, 0, false).await,
            Err(ClientError::InvalidArgument)
        ));
        assert_eq!(
            client
                .accept_stream(&application, &stream)
                .await
                .expect("accept loopback stream")
                .as_bytes(),
            stream.as_bytes()
        );
        assert!(matches!(
            client
                .write_stream_with_deadline(&stream, b"expired", false, Some(1))
                .await,
            Err(ClientError::DeadlineExceeded)
        ));
        assert_eq!(
            client
                .write_stream(&stream, b"hello", true)
                .await
                .expect("write"),
            5
        );
        let (data, eof) = client.read_stream(&stream, 64, false).await.expect("read");
        assert_eq!(data, b"hello");
        assert!(eof);

        client
            .send_datagram(&session, 9, b"datagram", 1_000, false)
            .await
            .expect("send datagram");
        let datagram = client
            .receive_datagram(&application, &session, 64, false)
            .await
            .expect("receive datagram");
        assert_eq!(datagram.context_id(), 9);
        assert_eq!(datagram.data(), b"datagram");

        client
            .close_listener(&listener)
            .await
            .expect("close listener");
        client
            .unregister_application(&application, true)
            .await
            .expect("unregister");
        client
            .unsubscribe_events(&subscription)
            .await
            .expect("unsubscribe events");
        assert!(matches!(
            client.write_stream(&stream, b"stale", false).await,
            Err(crate::ClientError::NotFound)
        ));
    }

    #[tokio::test]
    async fn embedded_connect_emits_typed_path_events_without_changing_session_handle() {
        let mut client = crate::Client::embedded();
        let endpoint = client.load_endpoint("default").await.expect("endpoint");
        let subscription = client
            .subscribe_events(crate::EventFilter {
                event_types: vec![api::EventType::PathChanged],
                ..Default::default()
            })
            .await
            .expect("subscription");
        let application = client
            .register_application(
                "path-test",
                [8u8; 16],
                &[endpoint.endpoint_id()],
                &["org.example.path/1"],
            )
            .await
            .expect("application");
        let session = client
            .connect_session(
                &application,
                &[6u8; 32],
                "org.example.path/1",
                &crate::Policy::default(),
            )
            .await
            .expect("session");
        let added = client.next_event(&subscription).await.expect("path added");
        assert_eq!(
            added.path_event(),
            Some(crate::PathEvent::Added {
                path_id: 0,
                carrier_type: "embedded-loopback".into(),
            })
        );
        assert_eq!(added.resource_handle(), Some(session.as_bytes()));
        client
            .acknowledge_event(&subscription, added.sequence())
            .await
            .expect("ack path added");
        let validated = client
            .next_event(&subscription)
            .await
            .expect("path validated");
        assert_eq!(
            validated.path_event(),
            Some(crate::PathEvent::Validated { path_id: 0 })
        );
        assert_eq!(validated.resource_handle(), Some(session.as_bytes()));
    }

    #[tokio::test]
    async fn embedded_close_link_reports_retirement_without_changing_session_handle() {
        let mut client = crate::Client::embedded();
        let endpoint = client.load_endpoint("default").await.expect("endpoint");
        let application = client
            .register_application(
                "close-link-test",
                [20u8; 16],
                &[endpoint.endpoint_id()],
                &["org.example.close-link/1"],
            )
            .await
            .expect("application");
        let session = client
            .connect_session(
                &application,
                &[21u8; 32],
                "org.example.close-link/1",
                &Policy::default(),
            )
            .await
            .expect("session");
        let subscription = client
            .subscribe_events(crate::EventFilter {
                event_types: vec![api::EventType::PathChanged],
                ..Default::default()
            })
            .await
            .expect("subscription");
        client
            .close_link(&session, "test close")
            .await
            .expect("close link");
        let retired = client
            .next_event(&subscription)
            .await
            .expect("retired path");
        assert_eq!(retired.resource_handle(), Some(session.as_bytes()));
        assert_eq!(
            retired.path_event(),
            Some(crate::PathEvent::Retired { path_id: 0 })
        );
    }

    #[tokio::test]
    async fn embedded_carrier_resource_surface_matches_daemon_shape() {
        let mut client = crate::Client::embedded();
        let types = client
            .request(
                "CarrierService",
                "ListCarrierTypes",
                api::ListCarrierTypesRequest::default().encode_to_vec(),
            )
            .await
            .expect("carrier types");
        assert_eq!(
            types.status.expect("status").code,
            api::StatusCode::Ok as i32
        );
        let types = api::ListCarrierTypesResponse::decode(types.payload.as_slice())
            .expect("carrier type response");
        assert_eq!(types.types.len(), 1);
        assert_eq!(types.types[0].type_id, "embedded-loopback");
        assert!(types.types[0].supports_dial);

        let instances = client
            .request(
                "CarrierService",
                "ListCarrierInstances",
                api::ListCarrierInstancesRequest::default().encode_to_vec(),
            )
            .await
            .expect("carrier instances");
        assert_eq!(
            instances.status.expect("status").code,
            api::StatusCode::Ok as i32
        );
        let instances = api::ListCarrierInstancesResponse::decode(instances.payload.as_slice())
            .expect("carrier instance response");
        assert_eq!(instances.instances.len(), 1);
        assert_eq!(
            instances.instances[0].state,
            api::CarrierInstanceState::Running as i32
        );
        assert!(!instances.instances[0]
            .carrier_handle
            .as_ref()
            .expect("carrier handle")
            .value
            .is_empty());
        let carrier_handle = instances.instances[0]
            .carrier_handle
            .clone()
            .expect("carrier handle");
        let stopped = client
            .request(
                "CarrierService",
                "StopCarrier",
                api::StopCarrierRequest {
                    carrier_handle: Some(carrier_handle.clone()),
                    drain_links: true,
                    drain_timeout_ms: 10,
                }
                .encode_to_vec(),
            )
            .await
            .expect("stop carrier");
        let stopped =
            api::StopCarrierResponse::decode(stopped.payload.as_slice()).expect("stop response");
        assert_eq!(
            stopped.instance.expect("stopped instance").state,
            api::CarrierInstanceState::Stopped as i32
        );
        let started = client
            .request(
                "CarrierService",
                "StartCarrier",
                api::StartCarrierRequest {
                    carrier_handle: Some(carrier_handle),
                }
                .encode_to_vec(),
            )
            .await
            .expect("start carrier");
        let started =
            api::StartCarrierResponse::decode(started.payload.as_slice()).expect("start response");
        assert_eq!(
            started.instance.expect("started instance").state,
            api::CarrierInstanceState::Running as i32
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn embedded_carrier_instances_factory_and_dial_are_owned() {
        let mut client = crate::Client::embedded();
        let created = client
            .request(
                "CarrierService",
                "CreateCarrierInstance",
                api::CreateCarrierInstanceRequest {
                    type_id: "embedded-loopback".into(),
                    label: "second".into(),
                    options: Vec::new(),
                    enabled: true,
                }
                .encode_to_vec(),
            )
            .await
            .expect("create carrier instance");
        let instance = api::CreateCarrierInstanceResponse::decode(created.payload.as_slice())
            .expect("create response")
            .instance
            .expect("instance");
        assert_eq!(instance.state, api::CarrierInstanceState::Created as i32);
        let handle = instance.carrier_handle.clone().expect("carrier handle");
        let started = client
            .request(
                "CarrierService",
                "StartCarrier",
                api::StartCarrierRequest {
                    carrier_handle: Some(handle.clone()),
                }
                .encode_to_vec(),
            )
            .await
            .expect("start carrier");
        assert_eq!(
            api::StartCarrierResponse::decode(started.payload.as_slice())
                .expect("start response")
                .instance
                .expect("started")
                .state,
            api::CarrierInstanceState::Running as i32
        );
        let dialed = client
            .request(
                "CarrierService",
                "Dial",
                api::DialRequest {
                    carrier_handle: Some(handle.clone()),
                    remote: "embedded://peer".into(),
                }
                .encode_to_vec(),
            )
            .await
            .expect("dial");
        let link = api::DialResponse::decode(dialed.payload.as_slice())
            .expect("dial response")
            .link
            .expect("link");
        let link_handle = link.link_handle.clone().expect("link handle");
        assert_eq!(link.carrier_handle, Some(handle.clone()));
        let listed = client
            .request(
                "CarrierService",
                "ListLinks",
                api::ListLinksRequest {
                    carrier_handle: Some(handle.clone()),
                    page: None,
                }
                .encode_to_vec(),
            )
            .await
            .expect("list links");
        let links = api::ListLinksResponse::decode(listed.payload.as_slice())
            .expect("links response")
            .links;
        assert!(links
            .iter()
            .any(|item| item.link_handle == Some(link_handle.clone())));
        client
            .request(
                "CarrierService",
                "CloseLink",
                api::CloseLinkRequest {
                    link_handle: Some(link_handle),
                    reason: "test".into(),
                }
                .encode_to_vec(),
            )
            .await
            .expect("close link");
        client
            .request(
                "CarrierService",
                "StopCarrier",
                api::StopCarrierRequest {
                    carrier_handle: Some(handle.clone()),
                    drain_links: true,
                    drain_timeout_ms: 0,
                }
                .encode_to_vec(),
            )
            .await
            .expect("stop carrier");
        client
            .request(
                "CarrierService",
                "DeleteCarrierInstance",
                api::DeleteCarrierInstanceRequest {
                    carrier_handle: Some(handle),
                    expected_revision: None,
                }
                .encode_to_vec(),
            )
            .await
            .expect("delete carrier");
    }

    #[tokio::test]
    async fn embedded_rejects_loopback_session_and_stream_with_protocol_errors() {
        let mut client = crate::Client::embedded();
        let endpoint = client.load_endpoint("default").await.expect("endpoint");
        let application = client
            .register_application(
                "reject-test",
                [4u8; 16],
                &[endpoint.endpoint_id()],
                &["org.example.reject/1"],
            )
            .await
            .expect("application");
        let session = client
            .connect_session(
                &application,
                &[5u8; 32],
                "org.example.reject/1",
                &crate::Policy::default(),
            )
            .await
            .expect("session");
        let stream = client
            .open_stream(&application, &session, false)
            .await
            .expect("stream");
        client
            .reject_stream(&stream, 77)
            .await
            .expect("reject stream");
        assert!(matches!(
            client.write_stream(&stream, b"rejected", false).await,
            Err(ClientError::NotFound)
        ));
        client
            .reject_session(&application, &session, 88, "test rejection")
            .await
            .expect("reject session");
        assert!(matches!(
            client.open_stream(&application, &session, false).await,
            Err(ClientError::NotFound)
        ));
    }

    #[tokio::test]
    async fn embedded_carrier_reports_loss_only_after_accepted_bytes_are_released() {
        let mut client = crate::Client::embedded_with_loopback_config(
            super::EmbeddedConfig::default(),
            crate::LoopbackCarrierConfig {
                drop_next_packets: 1,
                ..Default::default()
            },
        )
        .expect("loss-test backend");
        let endpoint = client.load_endpoint("default").await.expect("endpoint");
        let application = client
            .register_application(
                "loss-test",
                [11u8; 16],
                &[endpoint.endpoint_id()],
                &["org.example.loss/1"],
            )
            .await
            .expect("application");
        let session = client
            .connect_session(
                &application,
                &[4u8; 32],
                "org.example.loss/1",
                &crate::Policy::default(),
            )
            .await
            .expect("session");
        let subscription = client
            .subscribe_events(crate::EventFilter {
                event_types: vec![api::EventType::StreamState, api::EventType::PathChanged],
                ..Default::default()
            })
            .await
            .expect("subscription");
        let stream = client
            .open_stream(&application, &session, false)
            .await
            .expect("stream");
        assert_eq!(client.write_stream(&stream, b"lost", false).await, Ok(4));

        let opened = client
            .next_event(&subscription)
            .await
            .expect("stream opened");
        assert_eq!(opened.payload_type(), "stream_opened");
        let accepted = client.next_event(&subscription).await.expect("accepted");
        assert_eq!(accepted.payload_type(), "stream_bytes_accepted");
        let lost = client.next_event(&subscription).await.expect("lost");
        assert_eq!(
            lost.delivery_event(),
            Some(crate::DeliveryEvent::Lost {
                stream_id: 1,
                offset: 4,
            })
        );
        assert_eq!(lost.resource_handle(), Some(stream.as_bytes()));
        assert_eq!(
            client.read_stream(&stream, 64, false).await,
            Ok((Vec::new(), false))
        );
        let failed = client.next_event(&subscription).await.expect("path failed");
        assert_eq!(
            failed.path_event(),
            Some(crate::PathEvent::Failed { path_id: 0 })
        );
    }

    #[tokio::test]
    async fn persistent_embedded_backend_restores_identity_and_trust() {
        let root = std::env::temp_dir().join(format!(
            "umc-sdk-embedded-persistence-{}-{}",
            std::process::id(),
            super::now_ms()
        ));
        let config = super::EmbeddedConfig {
            endpoint_label: "persisted".into(),
        };
        let expected_endpoint = {
            let mut client = crate::Client::embedded_with_storage(
                config.clone(),
                &root,
                b"embedded-storage-test-password",
            )
            .expect("persistent backend");
            let endpoint = client.load_endpoint("persisted").await.expect("endpoint");
            let secondary = client
                .create_endpoint("secondary", 60_000)
                .await
                .expect("secondary endpoint");
            assert_ne!(secondary.endpoint_id(), endpoint.endpoint_id());
            let application = client
                .register_application(
                    "persistence-test",
                    [9u8; 16],
                    &[endpoint.endpoint_id()],
                    &["org.example.persistence/1"],
                )
                .await
                .expect("application");
            client
                .connect_session(
                    &application,
                    &[7u8; 32],
                    "org.example.persistence/1",
                    &crate::Policy::default(),
                )
                .await
                .expect("connect");
            endpoint.endpoint_id().to_vec()
        };

        let mut restarted =
            crate::Client::embedded_with_storage(config, &root, b"embedded-storage-test-password")
                .expect("restarted persistent backend");
        let restored = restarted
            .load_endpoint("persisted")
            .await
            .expect("restored");
        assert_eq!(restored.endpoint_id(), expected_endpoint.as_slice());
        let secondary = restarted
            .load_endpoint("secondary")
            .await
            .expect("restored secondary");
        assert_ne!(secondary.endpoint_id(), restored.endpoint_id());

        let store = umc_storage::sqlite::SqliteStore::open(&root.join("node.db"))
            .expect("storage database");
        let trust = umc_core::trust::TrustStore::new(&store, umc_core::trust::TrustState::Unknown);
        assert_eq!(
            trust
                .effective_trust_state(&[7u8; 32])
                .expect("trust record"),
            umc_core::trust::TrustState::Observed
        );
        assert!(matches!(
            crate::Client::embedded_with_storage(
                super::EmbeddedConfig {
                    endpoint_label: "persisted".into(),
                },
                &root,
                b"wrong-password",
            ),
            Err(ClientError::Internal(_))
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
