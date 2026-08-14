use std::path::PathBuf;
use std::time::Duration;
use umc_carrier::types::OutboundPacket;
use umc_carrier::Carrier;
use umc_crypto::signatures::IdentityKeyPair;
use umc_plugin::manifest::ExternalPluginManifest;
use umc_plugin::process::{PluginProcess, ProcessConfig};
use umc_plugin::runtime::ExternalCarrier;

#[cfg(any(unix, windows))]
#[tokio::test]
async fn external_plugin_completes_authenticated_lifecycle() {
    let command = PathBuf::from(env!("CARGO_BIN_EXE_umc-plugin-loopback"));
    let mut process = PluginProcess::spawn(
        ProcessConfig {
            command,
            plugin_name: "loopback-test".into(),
            granted_capabilities: vec!["datagram".into()],
            config_blob: b"test-config".to_vec(),
            startup_deadline: Duration::from_secs(2),
            ..ProcessConfig::default()
        },
        1,
    )
    .await
    .expect("loopback process must authenticate");

    process.heartbeat().await.expect("heartbeat ack");
    assert!(!process.heartbeat_expired(Duration::from_secs(1)));
    let listen = process
        .operation(
            umc_plugin::proto::umc::plugin::v1::OpType::Listen,
            0,
            b"127.0.0.1:0".to_vec(),
            Duration::from_secs(1),
        )
        .await
        .expect("listen response");
    assert_eq!(
        listen.status,
        umc_plugin::proto::umc::plugin::v1::OpStatus::Ok as i32
    );
    let send = process
        .operation(
            umc_plugin::proto::umc::plugin::v1::OpType::Send,
            listen.result_handle,
            b"opaque packet".to_vec(),
            Duration::from_secs(1),
        )
        .await
        .expect("send response");
    assert_eq!(send.result, b"opaque packet");
    process
        .shutdown(Duration::from_secs(1))
        .await
        .expect("graceful shutdown");
    assert!(process.exited().expect("process status"));
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn external_plugin_round_trips_large_payload_through_shared_region() {
    let command = PathBuf::from(env!("CARGO_BIN_EXE_umc-plugin-loopback"));
    let mut process = PluginProcess::spawn(
        ProcessConfig {
            command,
            plugin_name: "loopback-shared-memory".into(),
            granted_capabilities: vec!["datagram".into(), "shared-memory".into()],
            shared_memory_size: Some(64 * 1024),
            shared_memory_threshold: 1,
            startup_deadline: Duration::from_secs(2),
            ..ProcessConfig::default()
        },
        2,
    )
    .await
    .expect("loopback process must authenticate");
    let payload = vec![0x5a; 32 * 1024];
    let response = process
        .operation(
            umc_plugin::proto::umc::plugin::v1::OpType::Send,
            42,
            payload.clone(),
            Duration::from_secs(1),
        )
        .await
        .expect("shared payload response");
    assert_eq!(response.result, payload);
    process
        .shutdown(Duration::from_secs(1))
        .await
        .expect("graceful shutdown");
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn signed_manifest_allows_authenticated_plugin_launch() {
    let command = PathBuf::from(env!("CARGO_BIN_EXE_umc-plugin-loopback"));
    let signer = IdentityKeyPair::from_seed([11; 32]);
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("timestamp");
    let mut manifest = ExternalPluginManifest::new(
        "signed-loopback",
        (1, 0, 0),
        ExternalPluginManifest::executable_digest(&command).expect("digest"),
        vec!["datagram".into()],
        now_ms.saturating_sub(1_000),
        now_ms.saturating_add(60_000),
    );
    manifest.sign(&signer).expect("sign");
    let mut process = PluginProcess::spawn(
        ProcessConfig {
            command,
            plugin_name: "signed-loopback".into(),
            granted_capabilities: vec!["datagram".into()],
            manifest: Some(manifest),
            trusted_manifest_keys: vec![signer.public()],
            require_signed_manifest: true,
            startup_deadline: Duration::from_secs(2),
            ..ProcessConfig::default()
        },
        3,
    )
    .await
    .expect("signed plugin launch");
    process
        .shutdown(Duration::from_secs(1))
        .await
        .expect("graceful shutdown");
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn external_carrier_forwards_dial_send_and_close() {
    let carrier = ExternalCarrier::launch(
        "plugin:loopback".into(),
        ProcessConfig {
            command: PathBuf::from(env!("CARGO_BIN_EXE_umc-plugin-loopback")),
            plugin_name: "loopback-carrier".into(),
            granted_capabilities: vec!["datagram".into()],
            startup_deadline: Duration::from_secs(2),
            ..ProcessConfig::default()
        },
        ExternalCarrier::capabilities_for("plugin:loopback", false, true),
    )
    .expect("external carrier startup");
    let link = carrier.dial("loopback:1".into()).expect("dial");
    let result = link
        .send(OutboundPacket {
            bytes: b"opaque packet".to_vec(),
            control: false,
            deadline_ms: None,
        })
        .expect("send");
    assert!(matches!(
        result,
        umc_carrier::types::SendResult::Accepted { .. }
    ));
    link.close("test").expect("close link");
    carrier.shutdown().expect("shutdown");
}

#[cfg(any(unix, windows))]
#[test]
fn external_listener_accepts_plugin_link_event_and_translates_lifecycle() {
    let carrier = ExternalCarrier::launch(
        "plugin:loopback".into(),
        ProcessConfig {
            command: PathBuf::from(env!("CARGO_BIN_EXE_umc-plugin-loopback")),
            plugin_name: "loopback-listener".into(),
            granted_capabilities: vec!["datagram".into(), "listen".into()],
            startup_deadline: Duration::from_secs(2),
            ..ProcessConfig::default()
        },
        ExternalCarrier::capabilities_for("plugin:loopback", true, false),
    )
    .expect("external carrier startup");
    let listener = carrier.listen("127.0.0.1:0".into()).expect("listen");
    let link = listener.accept().expect("accepted link event");
    assert_eq!(
        link.events().expect("link active event"),
        umc_carrier::types::LinkEvent::Active
    );
    link.close("test").expect("close link");
    listener.close().expect("close listener");
    carrier.shutdown().expect("shutdown");
}

#[cfg(any(unix, windows))]
#[test]
fn external_carrier_discovery_returns_bounded_candidates() {
    let carrier = ExternalCarrier::launch(
        "plugin:loopback".into(),
        ProcessConfig {
            command: PathBuf::from(env!("CARGO_BIN_EXE_umc-plugin-loopback")),
            plugin_name: "loopback-discovery".into(),
            granted_capabilities: vec!["datagram".into(), "discovery".into()],
            startup_deadline: Duration::from_secs(2),
            ..ProcessConfig::default()
        },
        ExternalCarrier::capabilities_for_with_discovery("plugin:loopback", false, false, true),
    )
    .expect("external carrier startup");
    let batch = carrier
        .discover("public".into(), Duration::from_secs(1), 4)
        .expect("discovery");
    assert_eq!(batch.candidates.len(), 1);
    assert_eq!(batch.candidates[0].candidate_id, 77);
    assert_eq!(
        batch.candidates[0].source,
        umc_discovery::provider::CandidateSource::CarrierNative
    );
    carrier.shutdown().expect("shutdown");
}
