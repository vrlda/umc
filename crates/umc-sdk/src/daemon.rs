//! Low-level daemon connection (sdk.md §27): socket handshake plus raw
//! requests returning `(status_code, payload)`. Typed clients in
//! [`crate::client`], [`crate::config`], and [`crate::status`] build on
//! this.
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use umc_control::framing::{frame_envelope, EnvelopeDecoder};
use umc_control::proto::umc::api::v1 as api;

use crate::client::ClientError;

/// Connected daemon control socket with hello negotiation done.
#[derive(Debug)]
pub struct DaemonClient {
    stream: UnixStream,
    sequence: u64,
    request_id: u64,
    envelope_max: usize,
}

impl DaemonClient {
    /// Connects to the daemon's control socket and negotiates the API version.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Io`] when the socket cannot be connected, and
    /// [`ClientError::VersionMismatch`] or [`ClientError::Denied`] when the
    /// handshake is not accepted.
    pub async fn connect(socket: &str, client_name: &str) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(socket)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        let mut client = Self {
            stream,
            sequence: 1,
            request_id: 0,
            envelope_max: 4 * 1024 * 1024,
        };
        client.hello(client_name).await?;
        Ok(client)
    }

    /// Sends a request and returns the raw `(status_code, response_payload)`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Denied`] when the reply is not a Response
    /// envelope, and [`ClientError::Io`], [`ClientError::Framing`], or
    /// [`ClientError::Proto`] for transport and decode failures. Non-OK
    /// status codes are returned to the caller, not converted to errors.
    pub async fn request_raw(
        &mut self,
        service: &str,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<(i32, Vec<u8>), ClientError> {
        self.request_id += 1;
        let request = request_envelope(
            self.next_sequence(),
            self.request_id,
            service,
            method,
            payload,
        );
        self.send(&request).await?;
        let reply = self.recv_envelope().await?;
        match reply.body {
            Some(api::envelope::Body::Response(response)) => {
                let code = response.status.as_ref().map_or(0, |s| s.code);
                Ok((code, response.payload))
            }
            _ => Err(ClientError::Denied),
        }
    }

    async fn hello(&mut self, client_name: &str) -> Result<(), ClientError> {
        let hello = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: self.next_sequence(),
            body: Some(api::envelope::Body::ClientHello(api::ClientHello {
                supported_versions: vec![api::ApiVersion { major: 1, minor: 0 }],
                client_name: client_name.to_string(),
                ..Default::default()
            })),
        };
        self.send(&hello).await?;
        let reply = self.recv_envelope().await?;
        match reply.body {
            Some(api::envelope::Body::ServerHello(sh)) => {
                let version = sh.selected_version.ok_or(ClientError::VersionMismatch)?;
                if version.major != 1 {
                    return Err(ClientError::VersionMismatch);
                }
                self.envelope_max = usize::try_from(sh.negotiated_envelope_size.max(1024))
                    .unwrap_or(4 * 1024 * 1024);
                Ok(())
            }
            _ => Err(ClientError::Denied),
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence;
        self.sequence += 1;
        seq
    }

    async fn send(&mut self, envelope: &api::Envelope) -> Result<(), ClientError> {
        let mut bytes = Vec::new();
        Message::encode(envelope, &mut bytes).map_err(|e| ClientError::Proto(e.to_string()))?;
        let mut framed = Vec::new();
        frame_envelope(&mut framed, &bytes, self.envelope_max).map_err(ClientError::Framing)?;
        self.stream
            .write_all(&framed)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))
    }

    async fn recv_envelope(&mut self) -> Result<api::Envelope, ClientError> {
        let mut decoder = EnvelopeDecoder::new(self.envelope_max);
        let mut buf = [0u8; 8 * 1024];
        loop {
            let n = self
                .stream
                .read(&mut buf)
                .await
                .map_err(|e| ClientError::Io(e.to_string()))?;
            if n == 0 {
                return Err(ClientError::Io("connection closed".into()));
            }
            let envelopes = decoder.feed(&buf[..n]).map_err(ClientError::Framing)?;
            if let Some(envelope) = envelopes.first() {
                return api::Envelope::decode(envelope.as_slice())
                    .map_err(|e| ClientError::Proto(e.to_string()));
            }
        }
    }
}

fn request_envelope(
    sequence: u64,
    request_id: u64,
    service: &str,
    method: &str,
    payload: Vec<u8>,
) -> api::Envelope {
    api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence,
        body: Some(api::envelope::Body::Request(api::Request {
            request_id,
            service: service.to_string(),
            method: method.to_string(),
            payload,
            ..Default::default()
        })),
    }
}

/// Encodes a request envelope to bytes. Exposed for unit tests that pin the
/// wire shape without a live daemon.
///
/// # Errors
///
/// Returns [`ClientError::Proto`] when encoding fails.
#[cfg(test)]
pub(crate) fn encode_request(
    sequence: u64,
    request_id: u64,
    service: &str,
    method: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    let mut bytes = Vec::new();
    Message::encode(
        &request_envelope(sequence, request_id, service, method, payload),
        &mut bytes,
    )
    .map_err(|e| ClientError::Proto(e.to_string()))?;
    Ok(bytes)
}
