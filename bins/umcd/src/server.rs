//! Control socket server: Unix stream socket, framing, connection handling.
use crate::config::NodeConfig;
use crate::state::RuntimeState;
use prost::Message;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use umc_control::framing::{frame_envelope, EnvelopeDecoder};
use umc_control::proto::umc::api::v1 as api;
use umc_storage::sqlite::SqliteStore;

const DEFAULT_ENVELOPE_MAX: usize = 4 * 1024 * 1024;

pub async fn run(state: Arc<RuntimeState>) {
    let data_dir = state.config.resolved_data_dir();
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let store = state.store.clone();
    println!("data directory: {}", data_dir.display());

    if let Ok((profile, carriers)) = load_node_state(&store) {
        println!(
            "node state: profile {profile}, carriers [{}]",
            carriers.join(", ")
        );
    }
    persist_node_state(&store, &state.config).expect("persist node state");

    let socket_path = state.control_socket.clone();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).expect("socket dir");
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    println!("control socket: {}", socket_path.display());
    println!("node initialized");

    loop {
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(200)) => {
                if state.shutdown_requested.load(Ordering::Relaxed) {
                    break;
                }
            }
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    let store = store.clone();
                    tokio::spawn(handle_connection(stream, store));
                }
            }
        }
    }
    let _ = std::fs::remove_file(&socket_path);
    println!("control socket: closed");
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

/// Persist node state at shutdown and reload at startup (storage.md §22).
pub fn persist_node_state(store: &SqliteStore, config: &NodeConfig) -> Result<(), String> {
    use umc_storage::store::{Namespace, Store};
    store
        .put(Namespace::Config, b"profile", config.profile.as_bytes())
        .map_err(|e| format!("{e:?}"))?;
    let carriers = serde_json::to_vec(&config.carriers).map_err(|e| e.to_string())?;
    store
        .put(Namespace::Config, b"carriers", &carriers)
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

pub fn load_node_state(store: &SqliteStore) -> Result<(String, Vec<String>), String> {
    use umc_storage::store::{Namespace, Store};
    let profile = store
        .get(Namespace::Config, b"profile")
        .map_err(|e| format!("{e:?}"))?
        .map(|v| String::from_utf8(v).map_err(|_| "invalid profile".to_string()))
        .transpose()?
        .unwrap_or_else(|| "standard".to_string());
    let carriers = store
        .get(Namespace::Config, b"carriers")
        .map_err(|e| format!("{e:?}"))?
        .map(|v| serde_json::from_slice::<Vec<String>>(&v).map_err(|e| e.to_string()))
        .transpose()?
        .unwrap_or_default();
    Ok((profile, carriers))
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

    #[test]
    fn node_state_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("umcd-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.db");
        let _ = std::fs::remove_file(&path);
        let store = SqliteStore::open(&path).unwrap();
        let config = NodeConfig {
            profile: "relay".to_string(),
            carriers: vec!["ump.udp/1".to_string()],
            ..Default::default()
        };
        persist_node_state(&store, &config).unwrap();
        drop(store);

        let reopened = SqliteStore::open(&path).unwrap();
        let (profile, carriers) = load_node_state(&reopened).unwrap();
        assert_eq!(profile, "relay");
        assert_eq!(carriers, vec!["ump.udp/1"]);
    }
}
