//! Length-prefixed protobuf framing (carrier-plugin-api.md §11).
#![allow(clippy::missing_errors_doc)]
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DEFAULT_MAX_MESSAGE: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    ZeroLength,
    TooLarge,
    Truncated,
    Decode,
    Io,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ZeroLength => "zero-length frame",
            Self::TooLarge => "frame exceeds limit",
            Self::Truncated => "truncated frame",
            Self::Decode => "invalid protobuf frame",
            Self::Io => "plugin IPC I/O error",
        })
    }
}

impl std::error::Error for TransportError {}

pub fn frame_message(message: &[u8], max: usize) -> Result<Vec<u8>, TransportError> {
    if message.is_empty() {
        return Err(TransportError::ZeroLength);
    }
    if message.len() > max || message.len() > u32::MAX as usize {
        return Err(TransportError::TooLarge);
    }
    let mut framed = Vec::with_capacity(4 + message.len());
    let length = u32::try_from(message.len()).map_err(|_| TransportError::TooLarge)?;
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(message);
    Ok(framed)
}

pub fn encode_frame<M: Message>(message: &M, max: usize) -> Result<Vec<u8>, TransportError> {
    let bytes = message.encode_to_vec();
    frame_message(&bytes, max)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &[u8],
    max: usize,
) -> Result<(), TransportError> {
    let framed = frame_message(message, max)?;
    writer
        .write_all(&framed)
        .await
        .map_err(|_| TransportError::Io)
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut length = [0u8; 4];
    reader
        .read_exact(&mut length)
        .await
        .map_err(|_| TransportError::Truncated)?;
    let size = u32::from_be_bytes(length) as usize;
    if size == 0 {
        return Err(TransportError::ZeroLength);
    }
    if size > max || size > DEFAULT_MAX_MESSAGE {
        return Err(TransportError::TooLarge);
    }
    let mut body = vec![0u8; size];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| TransportError::Truncated)?;
    Ok(body)
}

pub async fn write_envelope<W: AsyncWrite + Unpin>(
    writer: &mut W,
    envelope: &crate::proto::umc::plugin::v1::PluginEnvelope,
    max: usize,
) -> Result<(), TransportError> {
    write_frame(writer, &envelope.encode_to_vec(), max).await
}

pub async fn read_envelope<R: AsyncRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> Result<crate::proto::umc::plugin::v1::PluginEnvelope, TransportError> {
    crate::proto::umc::plugin::v1::PluginEnvelope::decode(read_frame(reader, max).await?.as_slice())
        .map_err(|_| TransportError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::umc::plugin::v1 as p;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_round_trips_over_async_stream() {
        let envelope = p::PluginEnvelope {
            api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
            sequence: 7,
            body: Some(p::plugin_envelope::Body::Heartbeat(p::Heartbeat {
                sequence: 3,
            })),
        };
        let (mut left, mut right) = duplex(1024);
        let expected = envelope.clone();
        let writer = tokio::spawn(async move {
            write_envelope(&mut left, &envelope, DEFAULT_MAX_MESSAGE)
                .await
                .expect("write");
        });
        let decoded = read_envelope(&mut right, DEFAULT_MAX_MESSAGE)
            .await
            .expect("read");
        writer.await.expect("writer");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn empty_and_oversized_frames_rejected() {
        assert_eq!(frame_message(&[], 10), Err(TransportError::ZeroLength));
        assert_eq!(frame_message(&[0; 11], 10), Err(TransportError::TooLarge));
    }
}
