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

#[derive(Debug)]
pub enum ClientError {
    Io(String),
    Framing(umc_control::framing::FramingError),
    Proto(String),
    VersionMismatch,
    Denied,
    Unauthenticated,
    Unimplemented(String),
    Status(i32),
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
        let (code, response_payload) = self.daemon.request_raw(service, method, payload).await?;
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
