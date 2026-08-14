//! Compile-only daemon backend for platforms without Unix domain sockets or
//! Windows named pipes.
//!
//! Unix and Windows have real daemon transports. This module keeps the public
//! SDK surface available on other targets, while daemon-backed operations
//! return [`ClientError::Unsupported`].

#[cfg(test)]
use prost::Message;
#[cfg(test)]
use umc_control::proto::umc::api::v1 as api;

use crate::client::ClientError;
use crate::events::Event;

const UNSUPPORTED: &str = "daemon control transport is unavailable on this platform";

/// Placeholder daemon client for non-Unix targets.
#[derive(Debug)]
pub struct DaemonClient;

impl DaemonClient {
    /// Returns an explicit unsupported error on platforms without a daemon
    /// transport.
    ///
    /// # Errors
    ///
    /// Always returns [`ClientError::Unsupported`] on non-Unix platforms.
    pub async fn connect(socket: &str, client_name: &str) -> Result<Self, ClientError> {
        let _ = (socket, client_name);
        std::future::ready(Err(ClientError::Unsupported(UNSUPPORTED.into()))).await
    }

    /// Returns an explicit unsupported error on platforms without a daemon
    /// transport.
    ///
    /// # Errors
    ///
    /// Always returns [`ClientError::Unsupported`] on non-Unix platforms.
    pub async fn request_raw(
        &mut self,
        service: &str,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<(i32, Vec<u8>), ClientError> {
        let _ = (service, method, payload);
        std::future::ready(Err(ClientError::Unsupported(UNSUPPORTED.into()))).await
    }

    /// Returns an explicit unsupported error on platforms without a daemon
    /// transport.
    ///
    /// # Errors
    ///
    /// Always returns [`ClientError::Unsupported`] on non-Unix platforms.
    pub async fn request_raw_with_deadline(
        &mut self,
        service: &str,
        method: &str,
        payload: Vec<u8>,
        deadline_unix_ms: Option<i64>,
    ) -> Result<(i32, Vec<u8>), ClientError> {
        let _ = (service, method, payload, deadline_unix_ms);
        std::future::ready(Err(ClientError::Unsupported(UNSUPPORTED.into()))).await
    }

    pub(crate) async fn recv_event(&mut self, subscription: &[u8]) -> Result<Event, ClientError> {
        let _ = subscription;
        std::future::ready(Err(ClientError::Unsupported(UNSUPPORTED.into()))).await
    }

    pub(crate) async fn acknowledge_event(
        &mut self,
        subscription: &[u8],
        highest_contiguous_sequence: u64,
    ) -> Result<(), ClientError> {
        let _ = (subscription, highest_contiguous_sequence);
        std::future::ready(Err(ClientError::Unsupported(UNSUPPORTED.into()))).await
    }

    pub(crate) fn generation(&self) -> u64 {
        let _ = self;
        0
    }
}

#[cfg(test)]
fn request_envelope_with_deadline(
    sequence: u64,
    request_id: u64,
    service: &str,
    method: &str,
    payload: Vec<u8>,
    deadline_unix_ms: Option<i64>,
) -> api::Envelope {
    api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence,
        body: Some(api::envelope::Body::Request(api::Request {
            request_id,
            service: service.to_string(),
            method: method.to_string(),
            deadline_unix_ms: deadline_unix_ms.unwrap_or_default(),
            payload,
            ..Default::default()
        })),
    }
}

/// Encodes a request envelope for cross-platform SDK surface tests.
#[cfg(test)]
pub(crate) fn encode_request(
    sequence: u64,
    request_id: u64,
    service: &str,
    method: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    encode_request_with_deadline(sequence, request_id, service, method, payload, None)
}

/// Encodes a request with a deadline for cross-platform SDK surface tests.
#[cfg(test)]
pub(crate) fn encode_request_with_deadline(
    sequence: u64,
    request_id: u64,
    service: &str,
    method: &str,
    payload: Vec<u8>,
    deadline_unix_ms: Option<i64>,
) -> Result<Vec<u8>, ClientError> {
    let mut bytes = Vec::new();
    Message::encode(
        &request_envelope_with_deadline(
            sequence,
            request_id,
            service,
            method,
            payload,
            deadline_unix_ms,
        ),
        &mut bytes,
    )
    .map_err(|e| ClientError::Proto(e.to_string()))?;
    Ok(bytes)
}
