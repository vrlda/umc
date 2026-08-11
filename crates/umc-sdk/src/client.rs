//! Daemon-backed SDK client (sdk.md §27): typed requests over the low-level
//! [`crate::daemon::DaemonClient`].
use std::sync::Arc;
use umc_control::proto::umc::api::v1 as api;

use crate::daemon::DaemonClient;
use crate::embedded::{EmbeddedBackend, EmbeddedConfig};
use crate::embedded_transport::{LoopbackCarrier, LoopbackCarrierConfig};
use crate::events::Event;

#[derive(Debug)]
enum Backend {
    Daemon(DaemonClient),
    Embedded(Box<EmbeddedBackend>),
}

/// Connected daemon client with typed request decoding.
#[derive(Debug)]
pub struct Client {
    backend: Backend,
    request_id: u64,
    generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    Io(String),
    Framing(umc_control::framing::FramingError),
    Proto(String),
    VersionMismatch,
    Denied,
    Unauthenticated,
    Unimplemented(String),
    Status(i32),
    Authentication,
    PermissionDenied,
    InvalidArgument,
    NotFound,
    AlreadyExists,
    DeadlineExceeded,
    Cancelled,
    ResourceExhausted,
    FlowControl,
    StreamReset { stream_id: u64, error_code: u64 },
    StreamClosed,
    SessionClosed,
    SessionSuspended,
    Transport(String),
    Unavailable,
    DataLoss,
    Conflict,
    Internal(String),
    WouldBlock,
    Unsupported(String),
    HandleGenerationMismatch { expected: u64, actual: u64 },
    HandleTypeMismatch { expected: String, actual: String },
}

impl ClientError {
    /// Maps a Control API status into the SDK's stable error categories.
    #[must_use]
    pub fn from_status(code: i32) -> Self {
        match api::StatusCode::try_from(code).unwrap_or(api::StatusCode::Unknown) {
            api::StatusCode::Ok => Self::Internal("OK is not an error".into()),
            api::StatusCode::Cancelled => Self::Cancelled,
            api::StatusCode::InvalidArgument => Self::InvalidArgument,
            api::StatusCode::DeadlineExceeded => Self::DeadlineExceeded,
            api::StatusCode::NotFound => Self::NotFound,
            api::StatusCode::AlreadyExists => Self::AlreadyExists,
            api::StatusCode::PermissionDenied => Self::PermissionDenied,
            api::StatusCode::Unauthenticated => Self::Authentication,
            api::StatusCode::ResourceExhausted => Self::ResourceExhausted,
            api::StatusCode::Unimplemented => Self::Unimplemented("control-api".into()),
            api::StatusCode::Unavailable => Self::Unavailable,
            api::StatusCode::DataLoss => Self::DataLoss,
            api::StatusCode::Conflict => Self::Conflict,
            api::StatusCode::Unknown
            | api::StatusCode::FailedPrecondition
            | api::StatusCode::Aborted
            | api::StatusCode::OutOfRange
            | api::StatusCode::Internal
            | api::StatusCode::IdempotencyConflict => Self::Status(code),
        }
    }

    /// Maps a non-success response while preserving the operation name in
    /// the two legacy variants used by the original daemon client.
    #[must_use]
    pub fn from_status_for_method(code: i32, method: &str) -> Self {
        match api::StatusCode::try_from(code).unwrap_or(api::StatusCode::Unknown) {
            api::StatusCode::Unimplemented => Self::Unimplemented(method.to_string()),
            api::StatusCode::Unauthenticated => Self::Unauthenticated,
            _ => Self::from_status(code),
        }
    }
}

impl Client {
    /// Connects to the daemon's control socket and negotiates the API version.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Io`] when the socket cannot be connected, and
    /// [`ClientError::VersionMismatch`] or [`ClientError::Denied`] when the
    /// handshake is not accepted.
    pub async fn connect(socket: &str, client_name: &str) -> Result<Self, ClientError> {
        let daemon = DaemonClient::connect(socket, client_name).await?;
        let generation = daemon.generation();
        Ok(Self {
            backend: Backend::Daemon(daemon),
            request_id: 0,
            generation,
        })
    }

    /// Creates an in-process SDK client backed by the core runtime. The
    /// backend is explicit and never falls back to the daemon transport.
    ///
    /// # Panics
    /// The default configuration is fixed and valid; a panic indicates an
    /// internal backend-construction invariant was violated.
    #[must_use]
    pub fn embedded() -> Self {
        Self::embedded_with_config(EmbeddedConfig::default())
            .expect("default embedded backend configuration is valid")
    }

    /// Creates an in-process SDK client with explicit endpoint configuration.
    ///
    /// # Errors
    /// Returns [`ClientError::InvalidArgument`] for an empty or duplicate
    /// initial endpoint label.
    #[allow(clippy::needless_pass_by_value)]
    pub fn embedded_with_config(config: EmbeddedConfig) -> Result<Self, ClientError> {
        let backend = EmbeddedBackend::new(&config)?;
        let generation = backend.generation();
        Ok(Self {
            backend: Backend::Embedded(Box::new(backend)),
            request_id: 0,
            generation,
        })
    }

    /// Creates an embedded client using a caller-supplied carrier. The
    /// carrier owns packet delivery; the SDK only retains the bounded Link
    /// returned by `dial` for each embedded session.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidArgument`] for an invalid embedded
    /// configuration and [`ClientError::Internal`] when the carrier cannot
    /// be attached to the backend.
    #[allow(clippy::needless_pass_by_value)]
    pub fn embedded_with_carrier(
        config: EmbeddedConfig,
        carrier: Arc<dyn umc_carrier::Carrier + Send + Sync>,
    ) -> Result<Self, ClientError> {
        let backend = EmbeddedBackend::new_with_carrier(&config, carrier)?;
        let generation = backend.generation();
        Ok(Self {
            backend: Backend::Embedded(Box::new(backend)),
            request_id: 0,
            generation,
        })
    }

    /// Creates an embedded client with the built-in bounded loopback carrier.
    /// `drop_next_packets` is useful for deterministic terminal-loss tests.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidArgument`] for an invalid embedded
    /// configuration.
    #[allow(clippy::needless_pass_by_value)]
    pub fn embedded_with_loopback_config(
        config: EmbeddedConfig,
        carrier_config: LoopbackCarrierConfig,
    ) -> Result<Self, ClientError> {
        Self::embedded_with_carrier(config, Arc::new(LoopbackCarrier::new(carrier_config)))
    }

    /// Creates an embedded client with encrypted identity storage and a
    /// `SQLite` trust/peer store rooted at `storage_root`.
    ///
    /// The password is used only to unlock the embedded keystore and is never
    /// retained by the client after construction. Live sessions remain
    /// process-local and are intentionally not restored after a restart.
    ///
    /// # Errors
    /// Returns [`ClientError::Internal`] when the storage directory,
    /// keystore, or trust database cannot be opened or is corrupt.
    #[allow(clippy::needless_pass_by_value)]
    pub fn embedded_with_storage(
        config: EmbeddedConfig,
        storage_root: impl AsRef<std::path::Path>,
        storage_password: impl AsRef<[u8]>,
    ) -> Result<Self, ClientError> {
        let backend = EmbeddedBackend::new_with_storage(
            &config,
            storage_root.as_ref().to_path_buf(),
            storage_password.as_ref().to_vec(),
        )?;
        let generation = backend.generation();
        Ok(Self {
            backend: Backend::Embedded(Box::new(backend)),
            request_id: 0,
            generation,
        })
    }

    /// Returns whether this client executes requests in-process.
    #[must_use]
    pub fn is_embedded(&self) -> bool {
        matches!(&self.backend, Backend::Embedded(_))
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Sends a typed request and awaits the daemon's response.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Unimplemented`] for unknown methods,
    /// [`ClientError::Unauthenticated`] when the daemon requires a bearer
    /// credential this connection did not present, [`ClientError::Denied`]
    /// for unexpected envelopes, and [`ClientError::Io`],
    /// [`ClientError::Framing`], or [`ClientError::Proto`] for transport and
    /// decode failures.
    pub async fn request(
        &mut self,
        service: &str,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<api::Response, ClientError> {
        self.request_with_deadline(service, method, payload, None)
            .await
    }

    /// Sends a typed request with an optional absolute wall-clock deadline.
    /// `None` retains the legacy request behavior; callers performing work
    /// that can wait MUST pass a deadline to avoid an unbounded operation.
    ///
    /// # Errors
    ///
    /// Returns transport, framing, protocol, or mapped status errors.
    pub async fn request_with_deadline(
        &mut self,
        service: &str,
        method: &str,
        payload: Vec<u8>,
        deadline_unix_ms: Option<i64>,
    ) -> Result<api::Response, ClientError> {
        let (code, response_payload) = match &mut self.backend {
            Backend::Daemon(daemon) => {
                daemon
                    .request_raw_with_deadline(service, method, payload, deadline_unix_ms)
                    .await?
            }
            Backend::Embedded(embedded) => {
                embedded.request_raw(service, method, &payload, deadline_unix_ms)
            }
        };
        // Mirrors the daemon's request_id echo (server.rs `response_envelope`).
        self.request_id += 1;
        if code == api::StatusCode::Unimplemented as i32 {
            return Err(ClientError::Unimplemented(method.to_string()));
        }
        if code == api::StatusCode::Unauthenticated as i32 {
            return Err(ClientError::Unauthenticated);
        }
        Ok(api::Response {
            request_id: self.request_id,
            status: Some(api::Status {
                code,
                ..Default::default()
            }),
            payload: response_payload,
            ..Default::default()
        })
    }

    pub(crate) async fn recv_event(&mut self, subscription: &[u8]) -> Result<Event, ClientError> {
        match &mut self.backend {
            Backend::Daemon(daemon) => daemon.recv_event(subscription).await,
            Backend::Embedded(embedded) => embedded.next_event(subscription),
        }
    }

    pub(crate) async fn acknowledge_event_raw(
        &mut self,
        subscription: &[u8],
        highest_contiguous_sequence: u64,
    ) -> Result<(), ClientError> {
        match &mut self.backend {
            Backend::Daemon(daemon) => {
                daemon
                    .acknowledge_event(subscription, highest_contiguous_sequence)
                    .await
            }
            Backend::Embedded(embedded) => {
                embedded.acknowledge_event(subscription, highest_contiguous_sequence)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn connect_to_missing_socket_errors_gracefully() {
        let result = Client::connect("/nonexistent-umc-test.sock", "test").await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ClientError::Io(_))));
    }
}
