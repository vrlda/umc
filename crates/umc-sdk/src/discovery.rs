//! Typed discovery-provider access (discovery.md §6, §24).

use prost::Message;
use umc_control::proto::umc::api::v1;

use crate::client::{Client, ClientError};

/// A bounded candidate hint returned by the discovery provider.
///
/// Candidate metadata is intentionally non-secret: it contains no identity
/// private keys, session keys, or application payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryCandidate {
    pub candidate_id: u64,
    pub carrier_type: String,
    pub expires_at_ms: u64,
    pub public: bool,
}

/// An opaque application service advertisement. Metadata is returned without
/// interpretation; the endpoint is authenticated only when a later Connect
/// succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHint {
    pub peer_endpoint_id: Vec<u8>,
    pub protocol_id: String,
    pub endpoint_hint: Vec<u8>,
    pub metadata: Vec<u8>,
    pub expires_at_unix_ms: i64,
    pub signature: Vec<u8>,
    pub public: bool,
}

impl Client {
    /// Lists the local discovery-provider candidates.
    ///
    /// # Errors
    ///
    /// Returns a transport, protocol, or status error when the daemon or
    /// embedded backend cannot serve the bounded listing.
    pub async fn list_discovery_candidates(
        &mut self,
    ) -> Result<Vec<DiscoveryCandidate>, ClientError> {
        self.list_discovery_candidates_with_deadline(None).await
    }

    /// Lists discovery candidates with an absolute Control API deadline.
    ///
    /// # Errors
    ///
    /// Returns a transport, protocol, status, or deadline error.
    pub async fn list_discovery_candidates_with_deadline(
        &mut self,
        deadline_unix_ms: Option<i64>,
    ) -> Result<Vec<DiscoveryCandidate>, ClientError> {
        let payload = v1::ListCandidatesRequest {}.encode_to_vec();
        let response = self
            .request_with_deadline(
                "DiscoveryService",
                "ListCandidates",
                payload,
                deadline_unix_ms,
            )
            .await?;
        let status = response
            .status
            .as_ref()
            .map_or(v1::StatusCode::Ok as i32, |status| status.code);
        if status != v1::StatusCode::Ok as i32 {
            return Err(ClientError::from_status_for_method(
                status,
                "DiscoveryService.ListCandidates",
            ));
        }
        let listing = v1::ListCandidatesResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        Ok(listing
            .candidates
            .into_iter()
            .map(|candidate| DiscoveryCandidate {
                candidate_id: candidate.candidate_id,
                carrier_type: candidate.carrier_type,
                expires_at_ms: candidate.expires_at_ms,
                public: candidate.public,
            })
            .collect())
    }

    /// Publishes one locally signed opaque service hint.
    ///
    /// # Errors
    ///
    /// Returns a transport, protocol, status, or deadline error.
    pub async fn publish_service_hint(
        &mut self,
        protocol_id: String,
        endpoint_hint: Vec<u8>,
        metadata: Vec<u8>,
        expires_at_unix_ms: i64,
        public: bool,
    ) -> Result<ServiceHint, ClientError> {
        let payload = v1::PublishServiceHintRequest {
            protocol_id,
            endpoint_hint,
            metadata,
            expires_at_unix_ms,
            public,
        }
        .encode_to_vec();
        let response = self
            .request("DiscoveryService", "PublishServiceHint", payload)
            .await?;
        let status = response
            .status
            .as_ref()
            .map_or(v1::StatusCode::Ok as i32, |status| status.code);
        if status != v1::StatusCode::Ok as i32 {
            return Err(ClientError::from_status_for_method(
                status,
                "DiscoveryService.PublishServiceHint",
            ));
        }
        let hint = v1::PublishServiceHintResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?
            .hint
            .ok_or_else(|| ClientError::Proto("missing service hint".into()))?;
        Ok(ServiceHint {
            peer_endpoint_id: hint.peer_endpoint_id,
            protocol_id: hint.protocol_id,
            endpoint_hint: hint.endpoint_hint,
            metadata: hint.metadata,
            expires_at_unix_ms: hint.expires_at_unix_ms,
            signature: hint.signature,
            public: hint.public,
        })
    }

    /// Discovers active public service hints, optionally filtered by protocol.
    ///
    /// # Errors
    ///
    /// Returns a transport, protocol, status, or deadline error.
    pub async fn discover_services(
        &mut self,
        protocol_id: Option<String>,
    ) -> Result<Vec<ServiceHint>, ClientError> {
        let response = self
            .request(
                "DiscoveryService",
                "DiscoverServices",
                v1::DiscoverServicesRequest {
                    protocol_id: protocol_id.unwrap_or_default(),
                }
                .encode_to_vec(),
            )
            .await?;
        let status = response
            .status
            .as_ref()
            .map_or(v1::StatusCode::Ok as i32, |status| status.code);
        if status != v1::StatusCode::Ok as i32 {
            return Err(ClientError::from_status_for_method(
                status,
                "DiscoveryService.DiscoverServices",
            ));
        }
        let listing = v1::DiscoverServicesResponse::decode(response.payload.as_slice())
            .map_err(|error| ClientError::Proto(error.to_string()))?;
        Ok(listing
            .hints
            .into_iter()
            .map(|hint| ServiceHint {
                peer_endpoint_id: hint.peer_endpoint_id,
                protocol_id: hint.protocol_id,
                endpoint_hint: hint.endpoint_hint,
                metadata: hint.metadata,
                expires_at_unix_ms: hint.expires_at_unix_ms,
                signature: hint.signature,
                public: hint.public,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_candidate_is_non_secret_metadata() {
        let candidate = DiscoveryCandidate {
            candidate_id: 7,
            carrier_type: "ump.tcp/1".into(),
            expires_at_ms: 123,
            public: true,
        };
        assert_eq!(candidate.candidate_id, 7);
        assert!(candidate.public);
    }
}
