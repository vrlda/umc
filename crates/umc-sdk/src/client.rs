//! Daemon-backed SDK client (sdk.md §27): typed requests over the low-level
//! [`crate::daemon::DaemonClient`].
use umc_control::proto::umc::api::v1 as api;

use crate::daemon::DaemonClient;

/// Connected daemon client with typed request decoding.
#[derive(Debug)]
pub struct Client {
    daemon: DaemonClient,
    request_id: u64,
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
        Ok(Self {
            daemon: DaemonClient::connect(socket, client_name).await?,
            request_id: 0,
        })
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
        let (code, response_payload) = self
            .daemon
            .request_raw_with_deadline(service, method, payload, deadline_unix_ms)
            .await?;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_to_missing_socket_errors_gracefully() {
        let result = Client::connect("/nonexistent-umc-test.sock", "test").await;
        assert!(result.is_err());
        assert!(matches!(result, Err(ClientError::Io(_))));
    }
}
