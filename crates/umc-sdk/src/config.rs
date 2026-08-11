//! Node configuration client (control-api.md §29): reads and writes config
//! entries through the daemon's `NodeAdmin` service.
use std::collections::HashMap;

use prost::Message;
use umc_control::proto::umc::api::v1 as api;

use crate::client::ClientError;
use crate::daemon::DaemonClient;

/// Typed client for `NodeAdmin.GetConfig` and `NodeAdmin.UpdateConfig`.
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
        self.get_config_with_deadline(None).await
    }

    /// Returns config entries with an absolute Control API deadline.
    ///
    /// # Errors
    ///
    /// Returns a transport, deadline, status, or decode error.
    pub async fn get_config_with_deadline(
        &mut self,
        deadline_unix_ms: Option<i64>,
    ) -> Result<HashMap<String, String>, ClientError> {
        let (code, payload) = self
            .daemon
            .request_raw_with_deadline("NodeAdmin", "GetConfig", Vec::new(), deadline_unix_ms)
            .await?;
        if code != api::StatusCode::Ok as i32 {
            return Err(ClientError::from_status_for_method(
                code,
                "NodeAdmin.GetConfig",
            ));
        }
        let response = api::GetConfigResponse::decode(payload.as_slice())
            .map_err(|e| ClientError::Proto(e.to_string()))?;
        let mut entries = HashMap::new();
        for entry in response.config.into_iter().flat_map(|c| c.entries) {
            entries.insert(entry.key, entry.value);
        }
        Ok(entries)
    }

    /// Applies string-valued config writes atomically.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] (or its typed equivalent) when the
    /// daemon rejects a mutation, and [`ClientError::Proto`] when its success
    /// response cannot be decoded.
    pub async fn set_config(
        &mut self,
        entries: HashMap<String, String>,
    ) -> Result<(), ClientError> {
        self.set_config_with_deadline(entries, None).await
    }

    /// Applies config writes with an absolute Control API deadline.
    ///
    /// # Errors
    ///
    /// Returns a transport, deadline, status, or decode error.
    pub async fn set_config_with_deadline(
        &mut self,
        entries: HashMap<String, String>,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(), ClientError> {
        let payload = encode_update_config(entries)?;
        let (code, response_payload) = self
            .daemon
            .request_raw_with_deadline("NodeAdmin", "UpdateConfig", payload, deadline_unix_ms)
            .await?;
        if code != api::StatusCode::Ok as i32 {
            return Err(ClientError::from_status_for_method(
                code,
                "NodeAdmin.UpdateConfig",
            ));
        }
        api::UpdateConfigResponse::decode(response_payload.as_slice())
            .map_err(|e| ClientError::Proto(e.to_string()))?;
        Ok(())
    }
}

fn encode_update_config(entries: HashMap<String, String>) -> Result<Vec<u8>, ClientError> {
    let mut entries: Vec<_> = entries.into_iter().collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let request = api::UpdateConfigRequest {
        mutations: entries
            .into_iter()
            .map(|(key, value)| api::ConfigMutation {
                key,
                operation: Some(api::config_mutation::Operation::SetValue(value)),
            })
            .collect(),
        ..Default::default()
    };
    let mut payload = Vec::new();
    Message::encode(&request, &mut payload).map_err(|e| ClientError::Proto(e.to_string()))?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::encode_request;

    #[test]
    fn get_config_builds_config_service_request() {
        let bytes = encode_request(1, 1, "NodeAdmin", "GetConfig", Vec::new()).unwrap();
        let envelope = api::Envelope::decode(bytes.as_slice()).unwrap();
        let api::envelope::Body::Request(request) = envelope.body.unwrap() else {
            panic!("expected a request envelope");
        };
        assert_eq!(request.service, "NodeAdmin");
        assert_eq!(request.method, "GetConfig");
        assert!(request.payload.is_empty());
    }

    #[test]
    fn request_envelope_carries_payload() {
        let bytes = encode_request(2, 7, "NodeAdmin", "GetConfig", b"raw".to_vec()).unwrap();
        let envelope = api::Envelope::decode(bytes.as_slice()).unwrap();
        let api::envelope::Body::Request(request) = envelope.body.unwrap() else {
            panic!("expected a request envelope");
        };
        assert_eq!(request.request_id, 7);
        assert_eq!(request.payload, b"raw");
    }

    #[test]
    fn update_config_encodes_sorted_set_value_mutations() {
        let entries = HashMap::from([
            ("profile".to_string(), "standard".to_string()),
            ("mesh".to_string(), "true".to_string()),
        ]);
        let payload = encode_update_config(entries).unwrap();
        let decoded = api::UpdateConfigRequest::decode(payload.as_slice()).unwrap();
        assert_eq!(decoded.mutations.len(), 2);
        assert_eq!(decoded.mutations[0].key, "mesh");
        assert_eq!(decoded.mutations[1].key, "profile");
        assert!(matches!(
            decoded.mutations[0].operation,
            Some(api::config_mutation::Operation::SetValue(ref value)) if value == "true"
        ));
    }
}
