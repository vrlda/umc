//! Phase 2 integration: daemon lifecycle, hello, request/response, restart.
#![cfg(unix)]

use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, Command};
use umc_sdk::client::Client;

fn socket_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("umc-test-{}-{suffix}.sock", std::process::id()))
}

fn data_dir(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("umc-test-data-{}-{suffix}", std::process::id()))
}

/// Locate the umcd binary. `CARGO_BIN_EXE_<name>` is only set for a package's
/// own bins, and umcd is binary-only, so resolve via the target dir.
fn daemon_bin() -> PathBuf {
    let target = if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(dir)
    } else {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest).join("../../target")
    };
    target
        .join("debug")
        .join(format!("umcd{}", std::env::consts::EXE_SUFFIX))
}

fn spawn_daemon(suffix: &str) -> Child {
    let bin = daemon_bin();
    assert!(
        bin.exists(),
        "umcd binary missing at {}; run `cargo build -p umcd` first",
        bin.display()
    );
    let socket = socket_path(suffix);
    let _ = std::fs::remove_file(&socket);
    let data = data_dir(suffix);
    std::fs::create_dir_all(&data).unwrap();
    Command::new(bin)
        .arg("--socket")
        .arg(&socket)
        .env("HOME", data.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn umcd")
}

/// Poll until the daemon's control socket exists (startup grace loop).
async fn wait_for_socket(socket: &Path) {
    for _ in 0..50 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    panic!("daemon socket {} never appeared", socket.display());
}

async fn kill_child(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[tokio::test]
async fn daemon_accepts_hello_and_requests() {
    let suffix = "hello";
    let _ = std::fs::remove_dir_all(data_dir(suffix));
    let mut child = spawn_daemon(suffix);
    let socket = socket_path(suffix);
    wait_for_socket(&socket).await;
    let mut client = Client::connect(socket.to_str().unwrap(), "phase2-test")
        .await
        .expect("connect");
    let response = client
        .request("NodeAdmin", "GetStatus", Vec::new())
        .await
        .expect("request");
    assert_eq!(response.request_id, 1);
    kill_child(&mut child).await;
    let _ = std::fs::remove_file(&socket);
}

#[tokio::test]
async fn daemon_persists_state_across_restart() {
    let suffix = "restart";
    let _ = std::fs::remove_dir_all(data_dir(suffix));
    let mut child = spawn_daemon(suffix);
    let socket = socket_path(suffix);
    wait_for_socket(&socket).await;
    let mut client = Client::connect(socket.to_str().unwrap(), "phase2-test")
        .await
        .expect("connect");
    let response = client
        .request("NodeAdmin", "GetStatus", Vec::new())
        .await
        .expect("request");
    assert_eq!(response.request_id, 1);
    kill_child(&mut child).await;
    let _ = std::fs::remove_file(&socket);

    // Respawn against the same HOME data dir: state must survive.
    let mut child2 = spawn_daemon(suffix);
    wait_for_socket(&socket).await;
    let mut client2 = Client::connect(socket.to_str().unwrap(), "phase2-test")
        .await
        .expect("connect after restart");
    let response2 = client2
        .request("NodeAdmin", "GetStatus", Vec::new())
        .await
        .expect("request after restart");
    assert_eq!(response2.request_id, 1);
    kill_child(&mut child2).await;
    let _ = std::fs::remove_file(&socket);
}

#[tokio::test]
async fn malformed_implemented_methods_return_invalid_argument() {
    let suffix = "unimpl";
    let _ = std::fs::remove_dir_all(data_dir(suffix));
    let mut child = spawn_daemon(suffix);
    let socket = socket_path(suffix);
    wait_for_socket(&socket).await;
    let mut client = Client::connect(socket.to_str().unwrap(), "phase2-test")
        .await
        .expect("connect");
    let response = client
        .request("ApplicationService", "Connect", Vec::new())
        .await
        .expect("response");
    assert_eq!(
        response.status.expect("status").code,
        3, // Control API STATUS_CODE_INVALID_ARGUMENT.
    );
    kill_child(&mut child).await;
    let _ = std::fs::remove_file(&socket);
}
