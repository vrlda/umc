//! Minimal terminal-chat application built on the public Rust SDK.

use umc_sdk::{Client, ClientError, Policy};

pub const CHAT_PROTOCOL: &str = "org.example.chat/1";

/// Runs a deterministic local chat exchange through the embedded backend.
///
/// This is useful as a smoke test and as a starting point for a real terminal
/// frontend. The daemon-backed variant uses the same SDK calls after replacing
/// `Client::embedded()` with `Client::connect(...)`.
///
/// # Errors
/// Returns the first SDK transport, registration, stream, or teardown error.
pub async fn loopback_chat(messages: &[&[u8]]) -> Result<Vec<Vec<u8>>, ClientError> {
    let mut client = Client::embedded();
    let endpoint = client.load_endpoint("default").await?;
    let application = client
        .register_application(
            "terminal-chat",
            [0x43; 16],
            &[endpoint.endpoint_id()],
            &[CHAT_PROTOCOL],
        )
        .await?;
    let listener = client
        .listen(
            &application,
            endpoint.endpoint_id(),
            CHAT_PROTOCOL,
            &Policy::default(),
        )
        .await?;
    let pending_session = client
        .connect_session(
            &application,
            b"embedded-chat-peer",
            CHAT_PROTOCOL,
            &Policy::default(),
        )
        .await?;
    let session = client
        .accept_session(&application, &pending_session)
        .await?;
    let pending_stream = client.open_stream(&application, &session, false).await?;
    let stream = client.accept_stream(&application, &pending_stream).await?;

    let mut received = Vec::with_capacity(messages.len());
    for message in messages {
        client.write_stream(&stream, message, false).await?;
        let (data, eof) = client.read_stream(&stream, message.len(), false).await?;
        if eof {
            return Err(ClientError::StreamClosed);
        }
        received.push(data);
    }
    client.close_stream_send(&stream).await?;
    client.close_listener(&listener).await?;
    client.unregister_application(&application, true).await?;
    Ok(received)
}

#[cfg(test)]
mod tests {
    use super::loopback_chat;

    #[tokio::test]
    async fn chat_round_trips_interactive_messages_on_one_stream() {
        let received = loopback_chat(&[b"hello", b"mesh"]).await.expect("chat");
        assert_eq!(received, vec![b"hello".to_vec(), b"mesh".to_vec()]);
    }
}
