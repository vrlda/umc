//! Minimal reference external process used by the IPC integration test.
use std::env;
use std::io::{Read, Seek, SeekFrom, Write};
use umc_plugin::handshake::{API_VERSION_MAJOR, API_VERSION_MINOR};
use umc_plugin::proto::umc::plugin::v1 as p;
use umc_plugin::transport::{read_envelope, write_envelope, DEFAULT_MAX_MESSAGE};

#[tokio::main(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(any(unix, windows))]
    {
        let token = decode_hex(&env::var("UMC_PLUGIN_TOKEN")?)?;
        #[cfg(unix)]
        let mut stream = tokio::net::UnixStream::connect(env::var("UMC_PLUGIN_SOCKET")?).await?;
        #[cfg(windows)]
        let mut stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(env::var("UMC_PLUGIN_PIPE")?)?;
        write_envelope(
            &mut stream,
            &p::PluginEnvelope {
                api_version: Some(p::ApiVersion {
                    major: API_VERSION_MAJOR,
                    minor: API_VERSION_MINOR,
                }),
                sequence: 1,
                body: Some(p::plugin_envelope::Body::PluginHello(p::PluginHello {
                    api_version: Some(p::ApiVersion {
                        major: API_VERSION_MAJOR,
                        minor: API_VERSION_MINOR,
                    }),
                    plugin_name: env::var("UMC_PLUGIN_NAME").unwrap_or_else(|_| "loopback".into()),
                    supported_versions: vec![p::ApiVersion {
                        major: API_VERSION_MAJOR,
                        minor: API_VERSION_MINOR,
                    }],
                    capabilities: vec![
                        "datagram".into(),
                        "listen".into(),
                        "discovery".into(),
                        "shared-memory".into(),
                    ],
                    launch_token_proof: token,
                })),
            },
            DEFAULT_MAX_MESSAGE,
        )
        .await?;
        let _daemon_hello = read_envelope(&mut stream, DEFAULT_MAX_MESSAGE).await?;
        let config = read_envelope(&mut stream, DEFAULT_MAX_MESSAGE).await?;
        let shared_memory = match config.body {
            Some(p::plugin_envelope::Body::Config(config)) => config.shared_memory,
            _ => None,
        };
        write_envelope(
            &mut stream,
            &p::PluginEnvelope {
                api_version: Some(p::ApiVersion {
                    major: API_VERSION_MAJOR,
                    minor: API_VERSION_MINOR,
                }),
                sequence: 2,
                body: Some(p::plugin_envelope::Body::StartAck(p::StartAck {
                    started: true,
                    effective_config: "loopback".into(),
                })),
            },
            DEFAULT_MAX_MESSAGE,
        )
        .await?;
        loop {
            let envelope = read_envelope(&mut stream, DEFAULT_MAX_MESSAGE).await?;
            match envelope.body {
                Some(p::plugin_envelope::Body::Heartbeat(heartbeat)) => {
                    write_envelope(
                        &mut stream,
                        &p::PluginEnvelope {
                            api_version: Some(p::ApiVersion {
                                major: API_VERSION_MAJOR,
                                minor: API_VERSION_MINOR,
                            }),
                            sequence: envelope.sequence,
                            body: Some(p::plugin_envelope::Body::HeartbeatAck(p::HeartbeatAck {
                                sequence: heartbeat.sequence,
                            })),
                        },
                        DEFAULT_MAX_MESSAGE,
                    )
                    .await?;
                }
                Some(p::plugin_envelope::Body::OpReq(request)) => {
                    let request_arguments = if let (Some(reference), Some(memory)) =
                        (request.payload_ref.as_ref(), shared_memory.as_ref())
                    {
                        let mut file = std::fs::OpenOptions::new().read(true).open(&memory.path)?;
                        file.seek(SeekFrom::Start(reference.offset))?;
                        let length = usize::try_from(reference.length)?;
                        let mut bytes = vec![0; length];
                        file.read_exact(&mut bytes)?;
                        if reference.token != memory.token {
                            return Err("shared memory token mismatch".into());
                        }
                        bytes
                    } else {
                        request.arguments.clone()
                    };
                    let result_handle = match p::OpType::try_from(request.op_type).ok() {
                        Some(p::OpType::Listen | p::OpType::Dial) => 42,
                        _ => request.handle,
                    };
                    let mut result = request_arguments;
                    let payload_ref = if result.len() >= 16 * 1024 {
                        if let Some(memory) = shared_memory.as_ref() {
                            let mut file =
                                std::fs::OpenOptions::new().write(true).open(&memory.path)?;
                            file.seek(SeekFrom::Start(0))?;
                            file.write_all(&result)?;
                            file.sync_data()?;
                            let reference = p::PayloadRef {
                                offset: 0,
                                length: u64::try_from(result.len())?,
                                token: memory.token.clone(),
                            };
                            result.clear();
                            Some(reference)
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    write_envelope(
                        &mut stream,
                        &p::PluginEnvelope {
                            api_version: Some(p::ApiVersion {
                                major: API_VERSION_MAJOR,
                                minor: API_VERSION_MINOR,
                            }),
                            sequence: envelope.sequence,
                            body: Some(p::plugin_envelope::Body::OpResp(p::OpResp {
                                operation_id: request.operation_id,
                                status: p::OpStatus::Ok as i32,
                                result_handle,
                                result,
                                payload_ref,
                            })),
                        },
                        DEFAULT_MAX_MESSAGE,
                    )
                    .await?;
                    if matches!(
                        p::OpType::try_from(request.op_type).ok(),
                        Some(p::OpType::Listen)
                    ) {
                        write_envelope(
                            &mut stream,
                            &p::PluginEnvelope {
                                api_version: Some(p::ApiVersion {
                                    major: API_VERSION_MAJOR,
                                    minor: API_VERSION_MINOR,
                                }),
                                sequence: envelope.sequence.saturating_add(1),
                                body: Some(p::plugin_envelope::Body::Event(p::PluginEvent {
                                    event_type: p::EventType::LinkAccepted as i32,
                                    handle: 43,
                                    payload: b"loopback-peer".to_vec(),
                                })),
                            },
                            DEFAULT_MAX_MESSAGE,
                        )
                        .await?;
                        write_envelope(
                            &mut stream,
                            &p::PluginEnvelope {
                                api_version: Some(p::ApiVersion {
                                    major: API_VERSION_MAJOR,
                                    minor: API_VERSION_MINOR,
                                }),
                                sequence: envelope.sequence.saturating_add(2),
                                body: Some(p::plugin_envelope::Body::Event(p::PluginEvent {
                                    event_type: p::EventType::LinkActive as i32,
                                    handle: 43,
                                    payload: Vec::new(),
                                })),
                            },
                            DEFAULT_MAX_MESSAGE,
                        )
                        .await?;
                    }
                    if matches!(
                        p::OpType::try_from(request.op_type).ok(),
                        Some(p::OpType::Discover)
                    ) {
                        let candidate = p::Candidate {
                            candidate_id: 77,
                            carrier_type: "plugin:loopback".into(),
                            connection_hint: b"loopback:77".to_vec(),
                            lifetime_ms: 60_000,
                            authentication: 1,
                            sharing_policy: 3,
                            local: false,
                        };
                        write_envelope(
                            &mut stream,
                            &p::PluginEnvelope {
                                api_version: Some(p::ApiVersion {
                                    major: API_VERSION_MAJOR,
                                    minor: API_VERSION_MINOR,
                                }),
                                sequence: envelope.sequence.saturating_add(1),
                                body: Some(p::plugin_envelope::Body::Event(p::PluginEvent {
                                    event_type: p::EventType::CandidateFound as i32,
                                    handle: 0,
                                    payload: prost::Message::encode_to_vec(&candidate),
                                })),
                            },
                            DEFAULT_MAX_MESSAGE,
                        )
                        .await?;
                        write_envelope(
                            &mut stream,
                            &p::PluginEnvelope {
                                api_version: Some(p::ApiVersion {
                                    major: API_VERSION_MAJOR,
                                    minor: API_VERSION_MINOR,
                                }),
                                sequence: envelope.sequence.saturating_add(2),
                                body: Some(p::plugin_envelope::Body::Event(p::PluginEvent {
                                    event_type: p::EventType::DiscoveryComplete as i32,
                                    handle: 0,
                                    payload: Vec::new(),
                                })),
                            },
                            DEFAULT_MAX_MESSAGE,
                        )
                        .await?;
                    }
                }
                Some(
                    p::plugin_envelope::Body::Shutdown(_) | p::plugin_envelope::Body::Goaway(_),
                ) => return Ok(()),
                _ => {}
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if value.len() % 2 != 0 {
        return Err("odd hex token".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| Ok(u8::from_str_radix(&value[offset..offset + 2], 16)?))
        .collect()
}
