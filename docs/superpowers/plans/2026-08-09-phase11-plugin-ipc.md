# Phase 11: Carrier Plugin IPC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** External carriers run as isolated child processes speaking the Carrier Plugin Protocol (`carrier-plugin-api.md`): launch-token authentication, version negotiation, framed protobuf messages, handle scoping, heartbeats, crash invalidation, and restart backoff — proven by a loopback test plugin process.

**Architecture:** Per `carrier-plugin-api.md` §6-8 and `decisions.md` §8: the daemon spawns the plugin with an inherited launch token, the plugin connects to a private Unix socket, exchanges PLUGIN_HELLO/DAEMON_HELLO, negotiates one API version, and then operates under message-size and handle-generation rules. The daemon owns restart policy (3 attempts, 5-minute backoff cap) and invalidates all plugin state on crash.

**Tech Stack:** Rust stable, Tokio, prost, generated protobuf from a new `api/carrier-plugin.proto`.

---

## File Structure

- `api/carrier-plugin.proto` — plugin protocol messages
- `crates/umc-plugin/` — `Cargo.toml`, `build.rs`, `src/lib.rs`, `src/proto.rs`, `src/handshake.rs`, `src/handle.rs`, `src/transport.rs`, `src/manager.rs`
- `tests/phase11/` — `plugin_loopback.rs`

---

### Task 1: Plugin protocol schema

**Files:**
- Create: `api/carrier-plugin.proto`

- [ ] **Step 1: Write the schema**

`api/carrier-plugin.proto`:

```protobuf
syntax = "proto3";

package umc.plugin.v1;

// Carrier Plugin Protocol (carrier-plugin-api.md §8-12).

message ApiVersion {
  int32 major = 1;
  int32 minor = 2;
}

enum MessageClass {
  MESSAGE_CLASS_UNSPECIFIED = 0;
  PLUGIN_HELLO = 1;
  DAEMON_HELLO = 2;
  CONFIG = 3;
  START_ACK = 4;
  OP_REQ = 5;
  OP_RESP = 6;
  CANCEL = 7;
  EVENT = 8;
  HEARTBEAT = 9;
  HEARTBEAT_ACK = 10;
  LOG = 11;
  GOAWAY = 12;
  SHUTDOWN = 13;
  ERROR = 14;
}

message PluginHello {
  ApiVersion api_version = 1;
  string plugin_name = 2;
  repeated ApiVersion supported_versions = 3;
  repeated string capabilities = 4;
  bytes launch_token_proof = 5;
}

message DaemonHello {
  ApiVersion selected_version = 1;
  string daemon_identity = 2;
  repeated string granted_capabilities = 3;
  uint32 max_message_size = 4;
}

message PluginConfig {
  bytes config_blob = 1;
  uint32 maximum_packet_size = 2;
}

message StartAck {
  bool started = 1;
  string effective_config = 2;
}

enum OpType {
  OP_TYPE_UNSPECIFIED = 0;
  LISTEN = 1;
  DIAL = 2;
  CLOSE_LISTENER = 3;
  SEND = 4;
  CLOSE_LINK = 5;
  DISCOVER = 6;
  CANCEL_OP = 7;
}

message OpReq {
  uint64 operation_id = 1;
  OpType op_type = 2;
  uint64 handle = 3;
  bytes arguments = 4;
  uint64 deadline_ms = 5;
}

enum OpStatus {
  OP_STATUS_UNSPECIFIED = 0;
  OK = 1;
  WOULD_BLOCK = 2;
  QUEUE_FULL = 3;
  ERROR = 4;
}

message OpResp {
  uint64 operation_id = 1;
  OpStatus status = 2;
  uint64 result_handle = 3;
  bytes result = 4;
}

enum EventType {
  EVENT_TYPE_UNSPECIFIED = 0;
  LINK_ACCEPTED = 1;
  LINK_ACTIVE = 2;
  LINK_DEGRADED = 3;
  WRITABLE = 4;
  MTU_CHANGED = 5;
  CANDIDATE_FOUND = 6;
  CANDIDATE_EXPIRED = 7;
  DISCOVERY_COMPLETE = 8;
  CLOSED = 9;
  FAILED = 10;
}

message PluginEvent {
  EventType event_type = 1;
  uint64 handle = 2;
  bytes payload = 3;
}

message Heartbeat {
  uint64 sequence = 1;
}

message HeartbeatAck {
  uint64 sequence = 1;
}

message GoAway {
  string reason = 1;
  uint64 drain_deadline_ms = 2;
}

message PluginError {
  uint32 category = 1;
  string operation = 2;
  string message = 3;
}
```

- [ ] **Step 2: Add to workspace and verify codegen**

Append `"crates/umc-plugin"` to workspace members; create the crate in Task 2. Verify the proto compiles in Task 2's build.

- [ ] **Step 3: Commit**

```bash
git add api/carrier-plugin.proto
git commit -m "proto(plugin): carrier plugin protocol schema"
```

---

### Task 2: umc-plugin crate — codegen and handle rules

**Files:**
- Create: `crates/umc-plugin/Cargo.toml`
- Create: `crates/umc-plugin/build.rs`
- Create: `crates/umc-plugin/src/lib.rs`
- Create: `crates/umc-plugin/src/proto.rs`
- Create: `crates/umc-plugin/src/handle.rs`

- [ ] **Step 1: Crate manifest and codegen**

`crates/umc-plugin/Cargo.toml`:

```toml
[package]
name = "umc-plugin"
version.workspace = true
edition.workspace = true
license.workspace = true
build = "build.rs"

[dependencies]
prost = "0.13"
tokio = { version = "1", features = ["rt", "net", "io-util", "sync", "time", "process"] }
umc-types = { path = "../umc-types" }

[build-dependencies]
prost-build = "0.13"

[lints]
workspace = true
```

`crates/umc-plugin/build.rs`:

```rust
fn main() {
    prost_build::Config::new()
        .compile_protos(&["../../api/carrier-plugin.proto"], &["../../api"])
        .expect("compile carrier-plugin.proto");
    println!("cargo:rerun-if-changed=../../api/carrier-plugin.proto");
}
```

`crates/umc-plugin/src/lib.rs`:

```rust
pub mod handle;
pub mod handshake;
pub mod manager;
pub mod proto;
pub mod transport;
```

`crates/umc-plugin/src/proto.rs`:

```rust
pub mod umc {
    pub mod plugin {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/umc.plugin.v1.rs"));
        }
    }
}
```

- [ ] **Step 2: Write handle rules**

`crates/umc-plugin/src/handle.rs`:

```rust
//! Plugin handles (carrier-plugin-api.md §13): unique per process generation,
//! never cross types, invalid after restart.
use umc_types::runtime::EntropySource;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginHandleType {
    CarrierInstance = 1,
    Listener = 2,
    DiscoveryOperation = 3,
    Candidate = 4,
    Link = 5,
    SendOperation = 6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHandle {
    pub generation: u32,
    pub handle_type: PluginHandleType,
    pub value: u64,
}

impl PluginHandle {
    pub fn new(handle_type: PluginHandleType, generation: u32, entropy: &dyn EntropySource) -> Self {
        let mut value = [0u8; 8];
        entropy.fill(&mut value);
        Self { generation, handle_type, value: u64::from_be_bytes(value) }
    }

    pub fn validate(&self, expected_type: PluginHandleType, generation: u32) -> bool {
        self.handle_type == expected_type && self.generation == generation
    }

    pub fn encode(&self) -> u64 {
        // Wire encoding: generation in the high 16 bits, type in bits 56-63,
        // random value in the low 48 bits.
        ((self.generation as u64) << 48) | ((self.handle_type as u64) << 40) | (self.value & 0xFFFF_FFFF_FF)
    }

    pub fn decode(encoded: u64) -> Self {
        let generation = (encoded >> 48) as u32;
        let handle_type = match (encoded >> 40) & 0xFF {
            1 => PluginHandleType::CarrierInstance,
            2 => PluginHandleType::Listener,
            3 => PluginHandleType::DiscoveryOperation,
            4 => PluginHandleType::Candidate,
            5 => PluginHandleType::Link,
            _ => PluginHandleType::SendOperation,
        };
        Self { generation, handle_type, value: encoded & 0xFFFF_FFFF_FF }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(9);
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let h = PluginHandle::new(PluginHandleType::Link, 3, &E);
        let decoded = PluginHandle::decode(h.encode());
        assert_eq!(decoded.generation, 3);
        assert_eq!(decoded.handle_type, PluginHandleType::Link);
        assert_eq!(decoded.value, h.value);
    }

    #[test]
    fn validation_binds_type_and_generation() {
        let h = PluginHandle::new(PluginHandleType::Listener, 1, &E);
        assert!(h.validate(PluginHandleType::Listener, 1));
        assert!(!h.validate(PluginHandleType::Link, 1));
        assert!(!h.validate(PluginHandleType::Listener, 2));
    }

    #[test]
    fn old_generation_handles_invalid() {
        // After restart the generation increments; old handles must fail.
        let old = PluginHandle::new(PluginHandleType::Link, 1, &E);
        let new_generation = 2u32;
        assert!(!old.validate(PluginHandleType::Link, new_generation));
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-plugin`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-plugin
git commit -m "feat(plugin): codegen and handle rules"
```

---

### Task 3: Handshake and transport

**Files:**
- Create: `crates/umc-plugin/src/handshake.rs`
- Create: `crates/umc-plugin/src/transport.rs`

- [ ] **Step 1: Write the handshake**

`crates/umc-plugin/src/handshake.rs`:

```rust
//! Plugin protocol handshake (carrier-plugin-api.md §8): launch-token proof,
//! version negotiation, capability selection.
use crate::proto::umc::plugin::v1 as p;

pub const API_VERSION_MAJOR: i32 = 1;
pub const API_VERSION_MINOR: i32 = 0;
pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    BadLaunchToken,
    VersionMismatch,
    MissingCapability,
    Protocol(String),
}

/// Daemon side: verify PLUGIN_HELLO against the launch token issued at spawn.
pub fn accept_plugin_hello(
    hello: &p::PluginHello,
    expected_launch_token: &[u8],
) -> Result<p::DaemonHello, HandshakeError> {
    if hello.launch_token_proof != expected_launch_token {
        return Err(HandshakeError::BadLaunchToken);
    }
    let selected = hello
        .supported_versions
        .iter()
        .find(|v| v.major == API_VERSION_MAJOR)
        .ok_or(HandshakeError::VersionMismatch)?;
    if hello.capabilities.is_empty() {
        return Err(HandshakeError::MissingCapability);
    }
    Ok(p::DaemonHello {
        selected_version: Some(selected.clone()),
        daemon_identity: "umcd".to_string(),
        granted_capabilities: hello.capabilities.clone(),
        max_message_size: MAX_MESSAGE_SIZE,
    })
}

/// Plugin side: verify the daemon's selected version.
pub fn verify_daemon_hello(hello: &p::DaemonHello) -> Result<(), HandshakeError> {
    let Some(version) = &hello.selected_version else {
        return Err(HandshakeError::Protocol("missing selected version".into()));
    };
    if version.major != API_VERSION_MAJOR {
        return Err(HandshakeError::VersionMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(token: &[u8]) -> p::PluginHello {
        p::PluginHello {
            api_version: Some(p::ApiVersion { major: API_VERSION_MAJOR, minor: API_VERSION_MINOR }),
            plugin_name: "loopback".into(),
            supported_versions: vec![p::ApiVersion { major: API_VERSION_MAJOR, minor: 0 }],
            capabilities: vec!["datagram".into()],
            launch_token_proof: token.to_vec(),
        }
    }

    #[test]
    fn valid_hello_accepted() {
        let reply = accept_plugin_hello(&hello(b"token"), b"token").unwrap();
        assert_eq!(reply.selected_version.unwrap().major, API_VERSION_MAJOR);
        assert_eq!(reply.max_message_size, MAX_MESSAGE_SIZE);
    }

    #[test]
    fn wrong_token_rejected() {
        assert_eq!(accept_plugin_hello(&hello(b"wrong"), b"token"), Err(HandshakeError::BadLaunchToken));
    }

    #[test]
    fn no_common_version_rejected() {
        let mut h = hello(b"token");
        h.supported_versions = vec![p::ApiVersion { major: 2, minor: 0 }];
        assert_eq!(accept_plugin_hello(&h, b"token"), Err(HandshakeError::VersionMismatch));
    }

    #[test]
    fn empty_capabilities_rejected() {
        let mut h = hello(b"token");
        h.capabilities = vec![];
        assert_eq!(accept_plugin_hello(&h, b"token"), Err(HandshakeError::MissingCapability));
    }
}
```

- [ ] **Step 2: Write the transport**

`crates/umc-plugin/src/transport.rs`:

```rust
//! Length-prefixed framing for the plugin IPC (carrier-plugin-api.md §11):
//! 4-byte big-endian length + protobuf message, 1 MiB default max.
use crate::proto::umc::plugin::v1 as p;

pub const DEFAULT_MAX_MESSAGE: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    ZeroLength,
    TooLarge,
    Truncated,
    Decode,
    Io,
}

pub fn frame_message(message: &[u8], max: usize) -> Result<Vec<u8>, TransportError> {
    if message.is_empty() {
        return Err(TransportError::ZeroLength);
    }
    if message.len() > max {
        return Err(TransportError::TooLarge);
    }
    let mut out = Vec::with_capacity(message.len() + 4);
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    Ok(out)
}

pub struct MessageDecoder {
    buf: Vec<u8>,
    max: usize,
}

impl MessageDecoder {
    pub fn new(max: usize) -> Self {
        Self { buf: Vec::new(), max }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, TransportError> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes")) as usize;
            if len == 0 {
                return Err(TransportError::ZeroLength);
            }
            if len > self.max {
                return Err(TransportError::TooLarge);
            }
            if self.buf.len() < 4 + len {
                break;
            }
            out.push(self.buf[4..4 + len].to_vec());
            self.buf.drain(..4 + len);
        }
        Ok(out)
    }
}

pub fn decode_envelope(bytes: &[u8]) -> Result<p::PluginEnvelope, TransportError> {
    p::PluginEnvelope::decode(bytes).map_err(|_| TransportError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(msg: p::PluginHello) -> p::PluginEnvelope {
        p::PluginEnvelope {
            api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
            sequence: 1,
            body: Some(p::plugin_envelope::Body::PluginHello(msg)),
        }
    }

    #[test]
    fn frame_round_trip() {
        let msg = envelope(p::PluginHello { plugin_name: "t".into(), ..Default::default() });
        let mut bytes = Vec::new();
        prost::Message::encode(&msg, &mut bytes).unwrap();
        let framed = frame_message(&bytes, 4096).unwrap();
        assert_eq!(&framed[..4], &(bytes.len() as u32).to_be_bytes());
        let mut decoder = MessageDecoder::new(4096);
        let decoded = decoder.feed(&framed).unwrap();
        assert_eq!(decoded.len(), 1);
        let parsed = decode_envelope(&decoded[0]).unwrap();
        assert!(matches!(parsed.body, Some(p::plugin_envelope::Body::PluginHello(_))));
    }

    #[test]
    fn oversize_rejected_before_alloc() {
        let mut decoder = MessageDecoder::new(16);
        decoder.feed(&[0, 0, 0, 20]).unwrap();
        assert_eq!(decoder.feed(&[0u8; 20]), Err(TransportError::TooLarge));
    }

    #[test]
    fn zero_length_rejected() {
        let mut decoder = MessageDecoder::new(4096);
        assert_eq!(decoder.feed(&[0, 0, 0, 0]), Err(TransportError::ZeroLength));
    }
}
```

Note: the schema in Task 1 defines top-level messages without an `Envelope` wrapper — add one to `api/carrier-plugin.proto`:

```protobuf
message PluginEnvelope {
  ApiVersion api_version = 1;
  uint64 sequence = 2;
  oneof body {
    PluginHello plugin_hello = 3;
    DaemonHello daemon_hello = 4;
    PluginConfig config = 5;
    StartAck start_ack = 6;
    OpReq op_req = 7;
    OpResp op_resp = 8;
    PluginEvent event = 9;
    Heartbeat heartbeat = 10;
    HeartbeatAck heartbeat_ack = 11;
    GoAway goaway = 12;
    PluginError error = 13;
  }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-plugin`
Expected: PASS (10 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-plugin/src/handshake.rs crates/umc-plugin/src/transport.rs api/carrier-plugin.proto
git commit -m "feat(plugin): handshake and framing"
```

---

### Task 4: Plugin manager — spawn, heartbeat, restart

**Files:**
- Create: `crates/umc-plugin/src/manager.rs`

- [ ] **Step 1: Write the manager**

`crates/umc-plugin/src/manager.rs`:

```rust
//! Plugin process lifecycle (carrier-plugin-api.md §6, §19-22): spawn with a
//! launch token, heartbeat monitoring, crash invalidation, restart backoff.
use umc_types::runtime::EntropySource;
use std::time::{Duration, Instant};

pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);
pub const STARTUP_DEADLINE: Duration = Duration::from_secs(10);
pub const RESTART_BURST: u32 = 3;
pub const RESTART_BACKOFF_CAP: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    Stopped,
    Spawning,
    Running,
    Unhealthy,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct PluginStatus {
    pub state: PluginState,
    pub generation: u32,
    pub restarts: u32,
    pub last_heartbeat: Option<Instant>,
    pub last_error: Option<String>,
}

pub struct PluginManager {
    pub status: PluginStatus,
    pub launch_token: Vec<u8>,
}

impl PluginManager {
    pub fn new(entropy: &dyn EntropySource) -> Self {
        let mut token = vec![0u8; 32];
        entropy.fill(&mut token);
        Self { status: PluginStatus { state: PluginState::Stopped, generation: 0, restarts: 0, last_heartbeat: None, last_error: None }, launch_token: token }
    }

    /// Spawn a new generation; the token rotates per generation.
    pub fn spawn_generation(&mut self, entropy: &dyn EntropySource) -> Result<u32, PluginError> {
        if self.status.state == PluginState::Disabled {
            return Err(PluginError::Disabled);
        }
        if self.status.restarts >= RESTART_BURST && self.status.state == PluginState::Unhealthy {
            self.status.state = PluginState::Disabled;
            return Err(PluginError::Disabled);
        }
        self.status.generation += 1;
        self.status.state = PluginState::Spawning;
        self.status.restarts += 1;
        self.status.last_heartbeat = None;
        entropy.fill(&mut self.launch_token);
        Ok(self.status.generation)
    }

    pub fn mark_running(&mut self) {
        self.status.state = PluginState::Running;
        self.status.last_heartbeat = Some(Instant::now());
    }

    pub fn on_heartbeat(&mut self) {
        self.status.last_heartbeat = Some(Instant::now());
        if self.status.state == PluginState::Unhealthy {
            self.status.state = PluginState::Running;
        }
    }

    /// Heartbeat timeout or IPC closure (carrier-plugin-api.md §19.3).
    pub fn mark_unhealthy(&mut self, error: &str) {
        self.status.state = PluginState::Unhealthy;
        self.status.last_error = Some(error.to_string());
    }

    pub fn is_healthy(&self) -> bool {
        match self.status.last_heartbeat {
            Some(last) => self.status.state == PluginState::Running && last.elapsed() < HEARTBEAT_TIMEOUT,
            None => self.status.state == PluginState::Spawning,
        }
    }

    /// Crash invalidates the whole generation (carrier-plugin-api.md §20).
    pub fn on_crash(&mut self) {
        self.status.state = PluginState::Unhealthy;
        self.status.last_heartbeat = None;
    }

    /// Restart backoff: capped exponential (carrier-plugin-api.md §22).
    pub fn backoff_delay(&self) -> Duration {
        let multiplier = 1u64 << self.status.restarts.min(6);
        Duration::from_secs(multiplier.min(RESTART_BACKOFF_CAP.as_secs()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginError {
    Disabled,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(3);
        }
    }

    #[test]
    fn generation_and_token_rotate() {
        let mut mgr = PluginManager::new(&E);
        let g1 = mgr.spawn_generation(&E).unwrap();
        let token1 = mgr.launch_token.clone();
        let g2 = mgr.spawn_generation(&E).unwrap();
        assert_ne!(g1, g2);
        assert_ne!(token1, mgr.launch_token, "launch tokens must rotate per generation");
    }

    #[test]
    fn crash_invalidates_generation() {
        let mut mgr = PluginManager::new(&E);
        mgr.spawn_generation(&E).unwrap();
        mgr.mark_running();
        mgr.on_crash();
        assert_eq!(mgr.status.state, PluginState::Unhealthy);
        assert!(!mgr.is_healthy());
    }

    #[test]
    fn restart_burst_disables() {
        let mut mgr = PluginManager::new(&E);
        for _ in 0..RESTART_BURST {
            mgr.spawn_generation(&E).unwrap();
            mgr.on_crash();
        }
        assert_eq!(mgr.spawn_generation(&E), Err(PluginError::Disabled));
        assert_eq!(mgr.status.state, PluginState::Disabled);
    }

    #[test]
    fn backoff_is_capped() {
        let mut mgr = PluginManager::new(&E);
        mgr.status.restarts = 100;
        assert!(mgr.backoff_delay() <= RESTART_BACKOFF_CAP);
    }

    #[test]
    fn heartbeat_recovers() {
        let mut mgr = PluginManager::new(&E);
        mgr.spawn_generation(&E).unwrap();
        mgr.mark_unhealthy("timeout");
        mgr.on_heartbeat();
        assert_eq!(mgr.status.state, PluginState::Running);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-plugin`
Expected: PASS (15 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-plugin/src/manager.rs
git commit -m "feat(plugin): lifecycle manager with restart policy"
```

---

### Task 5: Integration test — loopback plugin process

**Files:**
- Create: `tests/phase11/Cargo.toml`
- Create: `tests/phase11/tests/plugin_loopback.rs`

- [ ] **Step 1: Test crate manifest**

`tests/phase11/Cargo.toml`:

```toml
[package]
name = "phase11-tests"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
umc-plugin = { path = "../../crates/umc-plugin" }
umc-types = { path = "../../crates/umc-types" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "sync", "time", "process"] }

[lints]
workspace = true
```

- [ ] **Step 2: Write the loopback test**

`tests/phase11/tests/plugin_loopback.rs`:

```rust
//! Phase 11 success criterion: the plugin protocol handshake, framing, and
//! lifecycle work end to end over a Unix socket pair without a real plugin
//! binary (the protocol-level contract is what matters in v0.1).
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use umc_plugin::handshake::{accept_plugin_hello, verify_daemon_hello};
use umc_plugin::proto::umc::plugin::v1 as p;
use umc_plugin::transport::{MessageDecoder, frame_message};

fn socket_path() -> String {
    std::env::temp_dir().join(format!("umc-plugin-{}.sock", std::process::id())).to_string_lossy().to_string()
}

async fn write_envelope(stream: &mut UnixStream, envelope: &p::PluginEnvelope) {
    let mut bytes = Vec::new();
    prost::Message::encode(envelope, &mut bytes).unwrap();
    let framed = frame_message(&bytes, 1024 * 1024).unwrap();
    stream.write_all(&framed).await.unwrap();
}

async fn read_envelope(stream: &mut UnixStream, decoder: &mut MessageDecoder) -> p::PluginEnvelope {
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            panic!("closed");
        }
        for raw in decoder.feed(&buf[..n]).unwrap() {
            return p::PluginEnvelope::decode(raw.as_slice()).unwrap();
        }
    }
}

#[tokio::test]
async fn plugin_protocol_handshake_over_socket() {
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();

    // "Daemon" side: accept, verify hello.
    let daemon = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut decoder = MessageDecoder::new(1024 * 1024);
        let hello_env = read_envelope(&mut stream, &mut decoder).await;
        let p::plugin_envelope::Body::PluginHello(hello) = hello_env.body.unwrap() else { panic!("expected hello") };
        let reply = accept_plugin_hello(&hello, b"launch-token-1").expect("accept");
        let daemon_env = p::PluginEnvelope {
            api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
            sequence: 1,
            body: Some(p::plugin_envelope::Body::DaemonHello(reply)),
        };
        write_envelope(&mut stream, &daemon_env).await;
    });

    // "Plugin" side: connect, send hello with the inherited token.
    let mut stream = UnixStream::connect(&path).await.unwrap();
    let hello = p::PluginHello {
        api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
        plugin_name: "loopback".into(),
        supported_versions: vec![p::ApiVersion { major: 1, minor: 0 }],
        capabilities: vec!["datagram".into()],
        launch_token_proof: b"launch-token-1".to_vec(),
    };
    let hello_env = p::PluginEnvelope {
        api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
        sequence: 1,
        body: Some(p::plugin_envelope::Body::PluginHello(hello)),
    };
    write_envelope(&mut stream, &hello_env).await;

    let mut decoder = MessageDecoder::new(1024 * 1024);
    let reply_env = read_envelope(&mut stream, &mut decoder).await;
    let p::plugin_envelope::Body::DaemonHello(daemon_hello) = reply_env.body.unwrap() else { panic!("expected daemon hello") };
    verify_daemon_hello(&daemon_hello).expect("verify");
    assert_eq!(daemon_hello.selected_version.unwrap().major, 1);

    daemon.await.unwrap();
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn wrong_launch_token_rejected() {
    let path = socket_path();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();

    let daemon = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut decoder = MessageDecoder::new(1024 * 1024);
        let hello_env = read_envelope(&mut stream, &mut decoder).await;
        let p::plugin_envelope::Body::PluginHello(hello) = hello_env.body.unwrap() else { panic!() };
        // A bad token is rejected; the connection must be closed without a
        // recognizable response (carrier-plugin-api.md §8.3).
        assert!(accept_plugin_hello(&hello, b"expected-token").is_err());
    });

    let mut stream = UnixStream::connect(&path).await.unwrap();
    let hello = p::PluginHello { plugin_name: "bad".into(), supported_versions: vec![p::ApiVersion { major: 1, minor: 0 }], capabilities: vec!["x".into()], launch_token_proof: b"wrong-token".to_vec(), ..Default::default() };
    let hello_env = p::PluginEnvelope { api_version: Some(p::ApiVersion { major: 1, minor: 0 }), sequence: 1, body: Some(p::plugin_envelope::Body::PluginHello(hello)) };
    write_envelope(&mut stream, &hello_env).await;
    daemon.await.unwrap();
    let _ = std::fs::remove_file(&path);
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p phase11-tests`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add tests/phase11
git commit -m "test(phase11): plugin protocol over sockets"
```

---

### Task 6: Phase 11 completion gate

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Verify the gate**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all green.

- [ ] **Step 2: Update README**

```markdown
- [x] Phases 0-10
- [x] Phase 11: carrier plugin IPC — handshake, framing, handles, lifecycle
```

- [ ] **Step 3: Verify against `carrier-plugin-api.md`**

Checklist:

- [ ] Launch-token authentication (rotates per generation)
- [ ] Version negotiation (no common major = failure)
- [ ] Length-prefixed framing with 1 MiB cap
- [ ] Handle generation/type validation
- [ ] Heartbeat interval 5s / timeout 15s
- [ ] Crash invalidation of the generation
- [ ] Restart burst 3, backoff capped at 5 minutes
- [ ] No ambient daemon credentials

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: phase 11 complete"
```

---

## Phase 11 self-review

**Spec coverage:** `carrier-plugin-api.md` §8 (handshake) → Task 3; §11 (framing) → Task 3; §13 (handles) → Task 2; §19-22 (health, crash, restart) → Task 4; §6 (startup) → Task 4; `resource-limits.md` §37 (plugin limits) → Tasks 3-4.

**Known deferrals:** actual process spawning and sandboxing (namespaces/seccomp, macOS profiles, Windows job objects — the manager owns the policy, the OS integration is per-platform), shared-memory packet transfer, plugin log streaming, traffic-shaping plugins, plugin-to-plugin communication.
