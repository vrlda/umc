//! Node configuration client (control-api.md §29): reads config entries from
//! the daemon. Writes are deferred to Phase 12.
use std::collections::HashMap;

use prost::Message;
use umc_control::proto::umc::api::v1 as api;

use crate::client::ClientError;
use crate::daemon::DaemonClient;

/// Typed client for `ConfigService.GetConfig`.
#[derive(Debug)]
pub struct ConfigClient {
    daemon: DaemonClient,
}

impl ConfigClient {
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

    /// Returns the node's config entries as `key -> value`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] when the daemon rejects the request,
    /// and [`ClientError::Proto`] when the response cannot be decoded.
    pub async fn get_config(&mut self) -> Result<HashMap<String, String>, ClientError> {
        let (code, payload) = self
            .daemon
            .request_raw("ConfigService", "GetConfig", Vec::new())
            .await?;
        if code != api::StatusCode::Ok as i32 {
            return Err(ClientError::Status(code));
        }
        let response = api::GetConfigResponse::decode(payload.as_slice())
            .map_err(|e| ClientError::Proto(e.to_string()))?;
        let mut entries = HashMap::new();
        for entry in response.config.into_iter().flat_map(|c| c.entries) {
            entries.insert(entry.key, entry.value);
        }
        Ok(entries)
    }

    /// Applies config writes; unimplemented until Phase 12 completes
    /// `ConfigService.UpdateConfig` plumbing.
    ///
    /// # Errors
    ///
    /// Always returns [`ClientError::Unimplemented`] today.
    pub fn set_config(&mut self, _entries: HashMap<String, String>) -> Result<(), ClientError> {
        Err(ClientError::Unimplemented(
            "ConfigService.UpdateConfig".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::encode_request;

    #[test]
    fn get_config_builds_config_service_request() {
        let bytes = encode_request(1, 1, "ConfigService", "GetConfig", Vec::new()).unwrap();
        let envelope = api::Envelope::decode(bytes.as_slice()).unwrap();
        let api::envelope::Body::Request(request) = envelope.body.unwrap() else {
            panic!("expected a request envelope");
        };
        assert_eq!(request.service, "ConfigService");
        assert_eq!(request.method, "GetConfig");
        assert!(request.payload.is_empty());
    }

    #[test]
    fn request_envelope_carries_payload() {
        let bytes = encode_request(2, 7, "ConfigService", "GetConfig", b"raw".to_vec()).unwrap();
        let envelope = api::Envelope::decode(bytes.as_slice()).unwrap();
        let api::envelope::Body::Request(request) = envelope.body.unwrap() else {
            panic!("expected a request envelope");
        };
        assert_eq!(request.request_id, 7);
        assert_eq!(request.payload, b"raw");
    }
}
