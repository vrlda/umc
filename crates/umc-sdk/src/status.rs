//! Node status client (control-api.md §28): typed snapshot reads.
use prost::Message;
use umc_control::proto::umc::api::v1 as api;

use crate::client::ClientError;
use crate::daemon::DaemonClient;

/// Typed snapshot of daemon state, decoded from `NodeAdmin.GetStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeStatusSnapshot {
    pub active_sessions: u32,
    pub active_links: u32,
    pub active_relay_circuits: u32,
    pub started_at_unix_ms: i64,
    pub uptime_ms: u64,
}

/// Typed client for `NodeAdmin.GetStatus`.
#[derive(Debug)]
pub struct StatusClient {
    daemon: DaemonClient,
}

impl StatusClient {
    /// Wraps an already-connected daemon client.
    #[must_use]
    pub fn new(daemon: DaemonClient) -> Self {
        Self { daemon }
    }

    /// Connects to the daemon's control socket and negotiates the API version.
    ///
    /// # Errors
    ///
    /// See [`DaemonClient::connect`].
    pub async fn connect(socket: &str, client_name: &str) -> Result<Self, ClientError> {
        Ok(Self {
            daemon: DaemonClient::connect(socket, client_name).await?,
        })
    }

    /// Returns a typed snapshot of the node's current state.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] when the daemon rejects the request,
    /// and [`ClientError::Proto`] when the response cannot be decoded.
    pub async fn get_status(&mut self) -> Result<NodeStatusSnapshot, ClientError> {
        self.get_status_with_deadline(None).await
    }

    /// Returns a status snapshot with an absolute Control API deadline.
    ///
    /// # Errors
    ///
    /// Returns a transport, deadline, status, or decode error.
    pub async fn get_status_with_deadline(
        &mut self,
        deadline_unix_ms: Option<i64>,
    ) -> Result<NodeStatusSnapshot, ClientError> {
        let (code, payload) = self
            .daemon
            .request_raw_with_deadline("NodeAdmin", "GetStatus", Vec::new(), deadline_unix_ms)
            .await?;
        if code != api::StatusCode::Ok as i32 {
            return Err(ClientError::from_status_for_method(
                code,
                "NodeAdmin.GetStatus",
            ));
        }
        let response = api::GetStatusResponse::decode(payload.as_slice())
            .map_err(|e| ClientError::Proto(e.to_string()))?;
        let status = response
            .status
            .ok_or_else(|| ClientError::Proto("missing status".into()))?;
        Ok(NodeStatusSnapshot {
            active_sessions: status.active_sessions,
            active_links: status.active_links,
            active_relay_circuits: status.active_relay_circuits,
            started_at_unix_ms: status.started_at_unix_ms,
            uptime_ms: status.uptime_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::encode_request;

    #[test]
    fn get_status_builds_node_admin_request() {
        let bytes = encode_request(1, 1, "NodeAdmin", "GetStatus", Vec::new()).unwrap();
        let envelope = api::Envelope::decode(bytes.as_slice()).unwrap();
        let api::envelope::Body::Request(request) = envelope.body.unwrap() else {
            panic!("expected a request envelope");
        };
        assert_eq!(request.service, "NodeAdmin");
        assert_eq!(request.method, "GetStatus");
        assert!(request.payload.is_empty());
    }
}
