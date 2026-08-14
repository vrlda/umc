//! Bounded, integrity-checked file transfer over an SDK stream.

use blake2::{Blake2s256, Digest};
use umc_sdk::{Client, ClientError, Policy, SDK_MAX_CHUNK_SIZE};

pub const FILE_PROTOCOL: &str = "mesh.community.files/1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferReport {
    pub bytes: usize,
    pub digest: [u8; 32],
    pub received: Vec<u8>,
}

/// Transfers `source` through a loopback UMC stream and verifies its digest.
///
/// `Client::embedded()` can be replaced with `Client::connect(...)` for a
/// daemon-backed application without changing the stream transfer logic.
///
/// # Errors
/// Returns the first SDK transport, registration, stream, or teardown error.
pub async fn transfer_bytes(source: &[u8]) -> Result<TransferReport, ClientError> {
    let mut client = Client::embedded();
    let endpoint = client.load_endpoint("default").await?;
    let application = client
        .register_application(
            "file-transfer",
            [0x46; 16],
            &[endpoint.endpoint_id()],
            &[FILE_PROTOCOL],
        )
        .await?;
    let listener = client
        .listen(
            &application,
            endpoint.endpoint_id(),
            FILE_PROTOCOL,
            &Policy::default(),
        )
        .await?;
    let pending_session = client
        .connect_session(
            &application,
            b"embedded-file-peer",
            FILE_PROTOCOL,
            &Policy::default(),
        )
        .await?;
    let session = client
        .accept_session(&application, &pending_session)
        .await?;
    let pending_stream = client.open_stream(&application, &session, false).await?;
    let stream = client.accept_stream(&application, &pending_stream).await?;
    client.write_stream(&stream, source, true).await?;

    let mut received = Vec::with_capacity(source.len());
    loop {
        let (chunk, eof) = client
            .read_stream(&stream, SDK_MAX_CHUNK_SIZE, false)
            .await?;
        received.extend_from_slice(&chunk);
        if eof {
            break;
        }
        if chunk.is_empty() {
            return Err(ClientError::Unavailable);
        }
    }
    client.close_listener(&listener).await?;
    client.unregister_application(&application, true).await?;

    let digest: [u8; 32] = Blake2s256::digest(&received).into();
    Ok(TransferReport {
        bytes: received.len(),
        digest,
        received,
    })
}

#[cfg(test)]
mod tests {
    use super::transfer_bytes;
    use blake2::Digest;

    #[tokio::test]
    async fn file_transfer_round_trips_large_payload_with_integrity() {
        let source: Vec<u8> = (0..(512 * 1024))
            .map(|index| u8::try_from(index % 251).expect("bounded pattern"))
            .collect();
        let report = transfer_bytes(&source).await.expect("transfer");
        assert_eq!(report.bytes, source.len());
        assert_eq!(report.received, source);
        assert_eq!(
            report.digest,
            blake2::Blake2s256::digest(&report.received).as_slice()
        );
    }
}
