//! Daemon-backed SDK client (sdk.md §27): connects to umcd, negotiates the
//! API version, and provides typed operations.
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use umc_control::framing::{frame_envelope, EnvelopeDecoder, FramingError};
use umc_control::proto::umc::api::v1 as api;

#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    sequence: u64,
    request_id: u64,
    envelope_max: usize,
}

#[derive(Debug)]
pub enum ClientError {
    Io(String),
    Framing(FramingError),
    Proto(String),
    VersionMismatch,
    Denied,
    Unauthenticated,
    Unimplemented(String),
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
        self.request_id += 1;
        let request = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: self.next_sequence(),
            body: Some(api::envelope::Body::Request(api::Request {
                request_id: self.request_id,
                service: service.to_string(),
                method: method.to_string(),
                payload,
                ..Default::default()
            })),
        };
        self.send(&request).await?;
        let reply = self.recv_envelope().await?;
        match reply.body {
            Some(api::envelope::Body::Response(response)) => {
                let code = response.status.as_ref().map_or(0, |s| s.code);
                if code == api::StatusCode::Unimplemented as i32 {
                    return Err(ClientError::Unimplemented(method.to_string()));
                }
                if code == api::StatusCode::Unauthenticated as i32 {
                    return Err(ClientError::Unauthenticated);
                }
                Ok(response)
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
