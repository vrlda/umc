//! Control socket server: Unix stream socket, framing, connection handling.
use crate::config::NodeConfig;
use prost::Message;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use umc_control::framing::{frame_envelope, EnvelopeDecoder};
use umc_control::proto::umc::api::v1 as api;
use umc_storage::sqlite::SqliteStore;

const DEFAULT_ENVELOPE_MAX: usize = 4 * 1024 * 1024;

pub async fn run(config: NodeConfig) {
    let data_dir = config.resolved_data_dir();
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let store = Arc::new(SqliteStore::open(&data_dir.join("node.db")).expect("open store"));
    println!("data directory: {}", data_dir.display());

    let socket_path = config.resolved_socket();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).expect("socket dir");
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    println!("control socket: {}", socket_path.display());
    println!("node initialized");

    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        let store = store.clone();
        tokio::spawn(handle_connection(stream, store));
    }
}

async fn handle_connection(mut stream: UnixStream, store: Arc<SqliteStore>) {
    let mut decoder = EnvelopeDecoder::new(DEFAULT_ENVELOPE_MAX);
    let mut buf = [0u8; 8 * 1024];
    loop {
        let Ok(n) = stream.read(&mut buf).await else {
            break;
        };
        if n == 0 {
            break;
        }
        let Ok(envelopes) = decoder.feed(&buf[..n]) else {
            break;
        };
        for envelope in envelopes {
            let Ok(msg) = api::Envelope::decode(envelope.as_slice()) else {
                break;
            };
            let response = match msg.body {
                Some(api::envelope::Body::ClientHello(hello)) => handle_hello(&hello, &store),
                Some(api::envelope::Body::Request(request)) => handle_request(&request, &store),
                _ => continue,
            };
            let mut out = Vec::new();
            if frame_envelope(&mut out, &response, DEFAULT_ENVELOPE_MAX).is_ok() {
                let _ = stream.write_all(&out).await;
            }
        }
    }
}

fn handle_hello(hello: &api::ClientHello, store: &SqliteStore) -> Vec<u8> {
    let _ = (hello, store);
    let server_hello = api::ServerHello {
        selected_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        node_state: 0,
        connection_id: vec![0u8; 16],
        principal_id: vec![],
        negotiated_envelope_size: u32::try_from(DEFAULT_ENVELOPE_MAX).expect("fits u32"),
        ..Default::default()
    };
    let envelope = api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence: 1,
        body: Some(api::envelope::Body::ServerHello(server_hello)),
    };
    let mut out = Vec::new();
    Message::encode(&envelope, &mut out).expect("encode");
    out
}

fn handle_request(request: &api::Request, store: &SqliteStore) -> Vec<u8> {
    let _ = store;
    let status = match request.method.as_str() {
        "GetStatus" => api::StatusCode::Ok,
        _ => api::StatusCode::Unimplemented,
    };
    let envelope = api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence: 1,
        body: Some(api::envelope::Body::Response(api::Response {
            request_id: request.request_id,
            status: Some(api::Status {
                code: status as i32,
                ..Default::default()
            }),
            ..Default::default()
        })),
    };
    let mut out = Vec::new();
    Message::encode(&envelope, &mut out).expect("encode");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_round_trip() {
        let hello = api::ClientHello {
            supported_versions: vec![api::ApiVersion { major: 1, minor: 0 }],
            ..Default::default()
        };
        let envelope = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: 1,
            body: Some(api::envelope::Body::ClientHello(hello)),
        };
        let mut bytes = Vec::new();
        Message::encode(&envelope, &mut bytes).unwrap();
        let decoded = api::Envelope::decode(bytes.as_slice()).unwrap();
        assert!(matches!(
            decoded.body,
            Some(api::envelope::Body::ClientHello(_))
        ));
    }
}
