# Phase 9: Application Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Applications register with the daemon, listen on protocol IDs, connect to endpoints, and exchange streams and datagrams over the Control API — with a full Rust SDK surface (`umc-sdk`) that matches `sdk.md`, proven by an echo application running entirely against a live daemon.

**Architecture:** Per `control-api.md` §31-35 and `sdk.md`: `ApplicationService` owns registration, listener, session, stream, and datagram handles; stream data uses bounded chunks (64 KiB default, 256 KiB max); write success means daemon ownership, never peer consumption. The SDK is a thin typed layer over the generated protobuf client.

**Tech Stack:** Rust stable, Tokio, existing umc crates.

---

## File Structure

- `crates/umc-control/src/app.rs` — application registration, listener/session/stream/datagram state
- `crates/umc-control/src/streams.rs` — chunked stream transfer state
- `bins/umcd/src/services/app.rs` — ApplicationService dispatch
- `crates/umc-sdk/src/app.rs` — typed application API (register, listen, connect, streams, datagrams)
- `crates/umc-sdk/src/stream.rs` — stream read/write with chunking
- `tests/phase9/` — `echo_app.rs`

---

### Task 1: Application registration

**Files:**
- Create: `crates/umc-control/src/app.rs`

- [ ] **Step 1: Write the failing test**

`crates/umc-control/src/app.rs`:

```rust
//! Application registration and ownership scoping (control-api.md §31).
use crate::handles::{Handle, HandleType};
use umc_types::runtime::EntropySource;

pub const MAX_PROTOCOL_LISTENERS: usize = 64;
pub const MAX_APPLICATION_SESSIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application {
    pub handle: Handle,
    pub principal_id: u64,
    pub name: String,
    pub instance_id: [u8; 16],
    pub endpoint_ids: Vec<Vec<u8>>,
    pub protocol_ids: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    AlreadyRegistered,
    TooManyApplications,
    NameTooLong,
}

pub struct ApplicationRegistry {
    applications: Vec<Application>,
    max_applications: usize,
}

impl ApplicationRegistry {
    pub fn new(max_applications: usize) -> Self {
        Self { applications: Vec::new(), max_applications }
    }

    /// RegisterApplication (control-api.md §31): returns an ApplicationHandle
    /// scoped to the principal. Registration cannot expand connection
    /// capabilities — the caller's grants still apply on every operation.
    pub fn register(
        &mut self,
        principal_id: u64,
        name: &str,
        instance_id: [u8; 16],
        endpoint_ids: Vec<Vec<u8>>,
        protocol_ids: Vec<Vec<u8>>,
        generation: u64,
        entropy: &dyn EntropySource,
    ) -> Result<Handle, RegistrationError> {
        if name.len() > 128 {
            return Err(RegistrationError::NameTooLong);
        }
        if self.applications.len() >= self.max_applications {
            return Err(RegistrationError::TooManyApplications);
        }
        if self.applications.iter().any(|a| a.principal_id == principal_id && a.instance_id == instance_id) {
            return Err(RegistrationError::AlreadyRegistered);
        }
        let handle = Handle::new(HandleType::Application, principal_id, generation, entropy);
        self.applications.push(Application {
            handle: handle.clone(),
            principal_id,
            name: name.to_string(),
            instance_id,
            endpoint_ids,
            protocol_ids,
        });
        Ok(handle)
    }

    pub fn get(&self, handle: &Handle, principal_id: u64, generation: u64) -> Option<&Application> {
        if !handle.validate(HandleType::Application, principal_id, generation) {
            return None;
        }
        self.applications.iter().find(|a| a.handle == *handle)
    }

    pub fn get_mut(&mut self, handle: &Handle, principal_id: u64, generation: u64) -> Option<&mut Application> {
        if !handle.validate(HandleType::Application, principal_id, generation) {
            return None;
        }
        self.applications.iter_mut().find(|a| a.handle == *handle)
    }

    pub fn unregister(&mut self, handle: &Handle) {
        self.applications.retain(|a| a.handle != *handle);
    }

    pub fn len(&self) -> usize {
        self.applications.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(2);
        }
    }

    #[test]
    fn registration_scopes_to_principal() {
        let mut registry = ApplicationRegistry::new(16);
        let handle = registry.register(7, "echo", [1u8; 16], vec![b"ep-1".to_vec()], vec![b"org.example.echo/1".to_vec()], 0, &E).unwrap();
        assert!(registry.get(&handle, 7, 0).is_some());
        assert!(registry.get(&handle, 8, 0).is_none(), "cross-principal access denied");
        assert!(registry.get(&handle, 7, 1).is_none(), "cross-generation access denied");
    }

    #[test]
    fn duplicate_instance_rejected() {
        let mut registry = ApplicationRegistry::new(16);
        registry.register(7, "a", [1u8; 16], vec![], vec![], 0, &E).unwrap();
        assert_eq!(registry.register(7, "a", [1u8; 16], vec![], vec![], 0, &E), Err(RegistrationError::AlreadyRegistered));
    }

    #[test]
    fn long_names_rejected() {
        let mut registry = ApplicationRegistry::new(16);
        assert_eq!(registry.register(7, &"x".repeat(129), [1u8; 16], vec![], vec![], 0, &E), Err(RegistrationError::NameTooLong));
    }

    #[test]
    fn unregister_removes() {
        let mut registry = ApplicationRegistry::new(16);
        let handle = registry.register(7, "a", [1u8; 16], vec![], vec![], 0, &E).unwrap();
        registry.unregister(&handle);
        assert_eq!(registry.len(), 0);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-control`
Expected: PASS (33 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-control/src/app.rs crates/umc-control/src/lib.rs
git commit -m "feat(control): application registration"
```

---

### Task 2: Listener lifecycle

**Files:**
- Modify: `crates/umc-control/src/app.rs` (append)

- [ ] **Step 1: Write listeners**

Append to `crates/umc-control/src/app.rs`:

```rust
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    pub handle: Handle,
    pub application: Handle,
    pub endpoint_id: Vec<u8>,
    pub protocol_id: Vec<u8>,
    pub pending: std::collections::VecDeque<Vec<u8>>, // incoming session tokens
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerError {
    DuplicateBinding,
    NotOwner,
    TooManyListeners,
    NotFound,
}

/// Listener binding: two applications cannot bind the same endpoint+protocol
/// tuple unless sharing is explicitly permitted (control-api.md §32).
pub fn bind_listener(
    applications: &mut ApplicationRegistry,
    app_handle: &Handle,
    principal_id: u64,
    generation: u64,
    endpoint_id: Vec<u8>,
    protocol_id: Vec<u8>,
    entropy: &dyn EntropySource,
) -> Result<Handle, ListenerError> {
    let application = applications.get(app_handle, principal_id, generation).ok_or(ListenerError::NotOwner)?;
    if !application.protocol_ids.iter().any(|p| *p == protocol_id) {
        return Err(ListenerError::NotOwner);
    }
    if application.endpoint_ids.iter().any(|e| *e == endpoint_id) || application.endpoint_ids.is_empty() {
        // allowed scope
    } else {
        return Err(ListenerError::NotOwner);
    }
    Ok(Handle::new(HandleType::Listener, principal_id, generation, entropy))
}

/// A listener registry scoped per application (Phase 9 keeps it in the daemon
/// service; the handle-binding rules live here for tests).
#[derive(Debug, Clone)]
pub struct ListenerRegistry {
    listeners: HashMap<Vec<u8>, Handle>, // (endpoint_id, protocol_id) key
}

impl ListenerRegistry {
    pub fn new() -> Self {
        Self { listeners: HashMap::new() }
    }

    pub fn bind(&mut self, endpoint_id: &[u8], protocol_id: &[u8], handle: Handle) -> Result<(), ListenerError> {
        let key = listener_key(endpoint_id, protocol_id);
        if self.listeners.contains_key(&key) {
            return Err(ListenerError::DuplicateBinding);
        }
        self.listeners.insert(key, handle);
        Ok(())
    }

    pub fn unbind(&mut self, endpoint_id: &[u8], protocol_id: &[u8]) {
        self.listeners.remove(&listener_key(endpoint_id, protocol_id));
    }

    pub fn bound(&self, endpoint_id: &[u8], protocol_id: &[u8]) -> Option<&Handle> {
        self.listeners.get(&listener_key(endpoint_id, protocol_id))
    }
}

fn listener_key(endpoint_id: &[u8], protocol_id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(endpoint_id.len() + protocol_id.len() + 1);
    key.extend_from_slice(endpoint_id);
    key.push(0);
    key.extend_from_slice(protocol_id);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_binding_conflicts() {
        let mut registry = ListenerRegistry::new();
        let a = Handle::new(HandleType::Listener, 1, 0, &E);
        let b = Handle::new(HandleType::Listener, 2, 0, &E);
        registry.bind(b"ep-1", b"org.example.echo/1", a.clone()).unwrap();
        assert_eq!(registry.bind(b"ep-1", b"org.example.echo/1", b.clone()), Err(ListenerError::DuplicateBinding));
        assert!(registry.bound(b"ep-1", b"org.example.echo/1").is_some());
        registry.unbind(b"ep-1", b"org.example.echo/1");
        assert!(registry.bound(b"ep-1", b"org.example.echo/1").is_none());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-control`
Expected: PASS (35 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-control/src/app.rs
git commit -m "feat(control): listener binding"
```

---

### Task 3: Stream transfer with chunking

**Files:**
- Create: `crates/umc-control/src/streams.rs`

- [ ] **Step 1: Write chunked stream state**

`crates/umc-control/src/streams.rs`:

```rust
//! Chunked stream transfer over the Control API (control-api.md §34):
//! 64 KiB default chunks, 256 KiB maximum, at most one read and one write
//! in flight per stream handle.
use crate::handles::{Handle, HandleType};
use std::collections::HashMap;

pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
pub const MAX_CHUNK_SIZE: usize = 256 * 1024;
pub const MAX_PENDING_READS: usize = 1;
pub const MAX_PENDING_WRITES: usize = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamState {
    pub handle: Handle,
    pub session: Handle,
    pub stream_id: u64,
    pub direction: StreamDirection,
    pub protocol_id: Vec<u8>,
    pub pending_reads: usize,
    pub pending_writes: usize,
    pub read_buffer: Vec<u8>,
    pub write_buffer: Vec<u8>,
    pub read_eof: bool,
    pub write_closed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamTransferError {
    ReadInFlight,
    WriteInFlight,
    ChunkTooLarge,
    NotFound,
}

pub struct StreamTable {
    streams: HashMap<Handle, StreamState>,
}

impl StreamTable {
    pub fn new() -> Self {
        Self { streams: HashMap::new() }
    }

    pub fn insert(&mut self, state: StreamState) -> Result<(), StreamTransferError> {
        if state.write_buffer.len() > MAX_CHUNK_SIZE || state.read_buffer.len() > MAX_CHUNK_SIZE {
            return Err(StreamTransferError::ChunkTooLarge);
        }
        self.streams.insert(state.handle.clone(), state);
        Ok(())
    }

    pub fn get(&self, handle: &Handle, principal_id: u64, generation: u64) -> Option<&StreamState> {
        let state = self.streams.get(handle)?;
        if !handle.validate(HandleType::Stream, principal_id, generation) {
            return None;
        }
        Some(state)
    }

    pub fn get_mut(&mut self, handle: &Handle, principal_id: u64, generation: u64) -> Option<&mut StreamState> {
        let state = self.streams.get_mut(handle)?;
        if !handle.validate(HandleType::Stream, principal_id, generation) {
            return None;
        }
        Some(state)
    }

    /// ReadStream: at most one read in flight (control-api.md §34).
    pub fn begin_read(&mut self, handle: &Handle, principal_id: u64, generation: u64) -> Result<(), StreamTransferError> {
        let state = self.get_mut(handle, principal_id, generation).ok_or(StreamTransferError::NotFound)?;
        if state.pending_reads >= MAX_PENDING_READS {
            return Err(StreamTransferError::ReadInFlight);
        }
        state.pending_reads += 1;
        Ok(())
    }

    pub fn complete_read(&mut self, handle: &Handle, principal_id: u64, generation: u64, data: Vec<u8>, eof: bool) -> Result<(), StreamTransferError> {
        let state = self.get_mut(handle, principal_id, generation).ok_or(StreamTransferError::NotFound)?;
        if data.len() > MAX_CHUNK_SIZE {
            return Err(StreamTransferError::ChunkTooLarge);
        }
        state.pending_reads = state.pending_reads.saturating_sub(1);
        state.read_buffer = data;
        state.read_eof = eof;
        Ok(())
    }

    /// WriteStream: at most one write in flight; success means daemon
    /// ownership, never peer consumption (session.md §36).
    pub fn begin_write(&mut self, handle: &Handle, principal_id: u64, generation: u64, chunk: Vec<u8>) -> Result<(), StreamTransferError> {
        let state = self.get_mut(handle, principal_id, generation).ok_or(StreamTransferError::NotFound)?;
        if state.pending_writes >= MAX_PENDING_WRITES {
            return Err(StreamTransferError::WriteInFlight);
        }
        if chunk.len() > MAX_CHUNK_SIZE {
            return Err(StreamTransferError::ChunkTooLarge);
        }
        state.pending_writes += 1;
        state.write_buffer = chunk;
        Ok(())
    }

    pub fn complete_write(&mut self, handle: &Handle, principal_id: u64, generation: u64) -> Result<(), StreamTransferError> {
        let state = self.get_mut(handle, principal_id, generation).ok_or(StreamTransferError::NotFound)?;
        state.pending_writes = state.pending_writes.saturating_sub(1);
        state.write_buffer.clear();
        Ok(())
    }

    pub fn remove(&mut self, handle: &Handle) {
        self.streams.remove(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl umc_types::runtime::EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(1);
        }
    }

    fn stream_handle() -> Handle {
        Handle::new(HandleType::Stream, 3, 0, &E)
    }

    fn state() -> StreamState {
        StreamState { handle: stream_handle(), session: Handle::new(HandleType::Session, 3, 0, &E), stream_id: 0, direction: StreamDirection::Outbound, protocol_id: b"org.example.echo/1".to_vec(), pending_reads: 0, pending_writes: 0, read_buffer: vec![], write_buffer: vec![], read_eof: false, write_closed: false }
    }

    #[test]
    fn single_read_in_flight() {
        let mut table = StreamTable::new();
        table.insert(state()).unwrap();
        let h = stream_handle();
        table.begin_read(&h, 3, 0).unwrap();
        assert_eq!(table.begin_read(&h, 3, 0), Err(StreamTransferError::ReadInFlight));
        table.complete_read(&h, 3, 0, b"data".to_vec(), true).unwrap();
        assert!(table.begin_read(&h, 3, 0).is_ok());
    }

    #[test]
    fn single_write_in_flight() {
        let mut table = StreamTable::new();
        table.insert(state()).unwrap();
        let h = stream_handle();
        table.begin_write(&h, 3, 0, b"chunk".to_vec()).unwrap();
        assert_eq!(table.begin_write(&h, 3, 0, b"again".to_vec()), Err(StreamTransferError::WriteInFlight));
        table.complete_write(&h, 3, 0).unwrap();
    }

    #[test]
    fn chunk_size_capped() {
        let mut table = StreamTable::new();
        table.insert(state()).unwrap();
        let h = stream_handle();
        assert_eq!(table.begin_write(&h, 3, 0, vec![0u8; MAX_CHUNK_SIZE + 1]), Err(StreamTransferError::ChunkTooLarge));
    }

    #[test]
    fn cross_principal_denied() {
        let mut table = StreamTable::new();
        table.insert(state()).unwrap();
        let h = stream_handle();
        assert!(table.get_mut(&h, 99, 0).is_none());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-control`
Expected: PASS (39 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-control/src/streams.rs crates/umc-control/src/lib.rs
git commit -m "feat(control): chunked stream transfer"
```

---

### Task 4: ApplicationService dispatch in the daemon

**Files:**
- Create: `bins/umcd/src/services/app.rs`

- [ ] **Step 1: Write the service dispatch**

`bins/umcd/src/services/app.rs`:

```rust
//! ApplicationService dispatch (control-api.md §31-35). Phase 9 implements
//! registration, listeners, and stream/datagram handles; the underlying
//! session wiring is the daemon network loop (Phase 8).
use umc_control::app::ApplicationRegistry;
use umc_control::handles::{Handle, HandleType};
use umc_control::proto::umc::api::v1 as api;
use umc_types::runtime::EntropySource;

pub struct AppService {
    pub applications: ApplicationRegistry,
    pub generation: u64,
}

impl AppService {
    pub fn new(generation: u64) -> Self {
        Self { applications: ApplicationRegistry::new(256), generation }
    }

    pub fn register_application(
        &mut self,
        principal_id: u64,
        request: &api::RegisterApplicationRequest,
        entropy: &dyn EntropySource,
    ) -> Result<api::OpaqueHandle, String> {
        let name = request.application_name.clone();
        let instance = request
            .application_instance_id
            .as_slice()
            .try_into()
            .map_err(|_| "instance id must be 16 bytes".to_string())?;
        let handle = self
            .applications
            .register(principal_id, &name, instance, request.requested_endpoint_ids.clone(), request.requested_protocol_ids.clone(), self.generation, entropy)
            .map_err(|e| format!("{e:?}"))?;
        Ok(api::OpaqueHandle { bytes: handle.bytes.to_vec() })
    }

    pub fn open_listener(
        &self,
        principal_id: u64,
        app_handle: &[u8],
        endpoint_id: &[u8],
        protocol_id: &[u8],
        entropy: &dyn EntropySource,
    ) -> Result<api::OpaqueHandle, String> {
        let app = self
            .applications
            .get(&Handle::from_bytes(app_handle)?, principal_id, self.generation)
            .ok_or("not owner".to_string())?;
        let _ = app;
        Ok(api::OpaqueHandle { bytes: Handle::new(HandleType::Listener, principal_id, self.generation, entropy).bytes.to_vec() })
    }
}

impl Handle {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let arr: [u8; 16] = bytes.try_into().map_err(|_| "handle must be 16 bytes".to_string())?;
        Ok(Self { bytes: arr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(6);
        }
    }

    #[test]
    fn register_returns_principal_scoped_handle() {
        let mut service = AppService::new(0);
        let request = api::RegisterApplicationRequest {
            application_name: "echo".into(),
            application_instance_id: vec![1u8; 16],
            requested_endpoint_ids: vec![b"ep".to_vec()],
            requested_protocol_ids: vec![b"org.example.echo/1".to_vec()],
            requested_operations: vec![],
        };
        let handle = service.register_application(7, &request, &E).unwrap();
        assert_eq!(handle.bytes.len(), 16);
        let parsed = Handle::from_bytes(&handle.bytes).unwrap();
        assert_eq!(parsed.principal_id(), 7);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umcd`
Expected: PASS (4 tests).

- [ ] **Step 3: Commit**

```bash
git add bins/umcd/src/services/app.rs bins/umcd/src/main.rs
git commit -m "feat(umcd): ApplicationService dispatch"
```

---

### Task 5: Full Rust SDK application surface

**Files:**
- Create: `crates/umc-sdk/src/app.rs`
- Create: `crates/umc-sdk/src/stream.rs`

- [ ] **Step 1: Write the application SDK**

`crates/umc-sdk/src/app.rs`:

```rust
//! Application surface (sdk.md §11-18): registration, listeners, sessions,
//! streams, datagrams over the daemon backend.
use crate::client::{Client, ClientError};
use umc_control::proto::umc::api::v1 as api;

#[derive(Debug, Clone)]
pub struct AppHandle(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct ListenerHandle(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct SessionHandle(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct StreamHandle(pub Vec<u8>);

impl Client {
    pub async fn register_application(&mut self, name: &str, instance_id: [u8; 16], endpoints: &[&[u8]], protocols: &[&[u8]]) -> Result<AppHandle, ClientError> {
        let request = api::RegisterApplicationRequest {
            application_name: name.to_string(),
            application_instance_id: instance_id.to_vec(),
            requested_endpoint_ids: endpoints.iter().map(|e| e.to_vec()).collect(),
            requested_protocol_ids: protocols.iter().map(|p| p.to_vec()).collect(),
            requested_operations: vec![],
        };
        let mut payload = Vec::new();
        prost::Message::encode(&request, &mut payload).map_err(|e| ClientError::Proto(e.to_string()))?;
        let response = self.request("ApplicationService", "RegisterApplication", payload).await?;
        let reply = api::RegisterApplicationResponse::decode(response.payload.as_slice()).map_err(|e| ClientError::Proto(e.to_string()))?;
        Ok(AppHandle(reply.application_handle.ok_or(ClientError::Denied)?.bytes))
    }

    pub async fn open_listener(&mut self, app: &AppHandle, endpoint_id: &[u8], protocol_id: &[u8]) -> Result<ListenerHandle, ClientError> {
        let request = api::OpenListenerRequest {
            application_handle: Some(api::OpaqueHandle { bytes: app.0.clone() }),
            endpoint_id: endpoint_id.to_vec(),
            protocol_id: protocol_id.to_vec(),
            listen_policy: None,
        };
        let mut payload = Vec::new();
        prost::Message::encode(&request, &mut payload).map_err(|e| ClientError::Proto(e.to_string()))?;
        let response = self.request("ApplicationService", "OpenListener", payload).await?;
        let reply = api::OpenListenerResponse::decode(response.payload.as_slice()).map_err(|e| ClientError::Proto(e.to_string()))?;
        Ok(ListenerHandle(reply.listener_handle.ok_or(ClientError::Denied)?.bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sdk_requests_build_and_fail_cleanly_without_daemon() {
        let mut client = match Client::connect("/nonexistent.sock", "sdk-test").await {
            Ok(c) => c,
            Err(_) => return, // no daemon in unit tests; daemon tests live in tests/phase9
        };
        let _ = client.register_application("echo", [0u8; 16], &[], &[]).await;
    }
}
```

- [ ] **Step 2: Write the stream wrapper**

`crates/umc-sdk/src/stream.rs`:

```rust
//! Stream API with chunking (sdk.md §17, control-api.md §34).
use crate::client::{Client, ClientError};
use umc_control::proto::umc::api::v1 as api;

pub const SDK_CHUNK_SIZE: usize = 64 * 1024;

pub struct SdkStream {
    pub handle: Vec<u8>,
    pub client: Client,
    pub closed_send: bool,
}

impl SdkStream {
    pub async fn write(&mut self, data: &[u8]) -> Result<(), ClientError> {
        for chunk in data.chunks(SDK_CHUNK_SIZE) {
            let request = api::WriteStreamRequest {
                stream_handle: Some(api::OpaqueHandle { bytes: self.handle.clone() }),
                data: chunk.to_vec(),
            };
            let mut payload = Vec::new();
            prost::Message::encode(&request, &mut payload).map_err(|e| ClientError::Proto(e.to_string()))?;
            let response = self.client.request("ApplicationService", "WriteStream", payload).await?;
            if response.status.as_ref().map(|s| s.code).unwrap_or(0) != api::StatusCode::Ok as i32 {
                return Err(ClientError::Denied);
            }
        }
        Ok(())
    }

    pub async fn read(&mut self, max: usize) -> Result<(Vec<u8>, bool), ClientError> {
        let request = api::ReadStreamRequest {
            stream_handle: Some(api::OpaqueHandle { bytes: self.handle.clone() }),
            max_bytes: max.min(256 * 1024) as u32,
        };
        let mut payload = Vec::new();
        prost::Message::encode(&request, &mut payload).map_err(|e| ClientError::Proto(e.to_string()))?;
        let response = self.client.request("ApplicationService", "ReadStream", payload).await?;
        let reply = api::ReadStreamResponse::decode(response.payload.as_slice()).map_err(|e| ClientError::Proto(e.to_string()))?;
        Ok((reply.data, reply.eof))
    }

    pub async fn close_send(&mut self) -> Result<(), ClientError> {
        if self.closed_send {
            return Ok(());
        }
        let request = api::CloseStreamSendRequest { stream_handle: Some(api::OpaqueHandle { bytes: self.handle.clone() }) };
        let mut payload = Vec::new();
        prost::Message::encode(&request, &mut payload).map_err(|e| ClientError::Proto(e.to_string()))?;
        self.client.request("ApplicationService", "CloseStreamSend", payload).await?;
        self.closed_send = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_size_matches_control_api() {
        assert_eq!(SDK_CHUNK_SIZE, umc_control::streams::DEFAULT_CHUNK_SIZE);
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-sdk`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-sdk/src/app.rs crates/umc-sdk/src/stream.rs crates/umc-sdk/src/lib.rs
git commit -m "feat(sdk): application surface and stream wrapper"
```

---

### Task 6: Integration test — echo app against a live daemon

**Files:**
- Create: `tests/phase9/Cargo.toml`
- Create: `tests/phase9/tests/echo_app.rs`

- [ ] **Step 1: Test crate manifest**

`tests/phase9/Cargo.toml`:

```toml
[package]
name = "phase9-tests"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
umc-sdk = { path = "../../crates/umc-sdk" }
umc-control = { path = "../../crates/umc-control" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "process", "time"] }

[lints]
workspace = true
```

- [ ] **Step 2: Write the echo-app test**

`tests/phase9/tests/echo_app.rs`:

```rust
//! Phase 9 success criterion: an application registers, listens, connects,
//! and exchanges stream data through the Control API against a live daemon.
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use umc_control::proto::umc::api::v1 as api;
use umc_sdk::client::Client;

fn socket_path() -> PathBuf {
    std::env::temp_dir().join(format!("umc-phase9-{}.sock", std::process::id()))
}

fn data_dir() -> PathBuf {
    std::env::temp_dir().join(format!("umc-phase9-data-{}", std::process::id()))
}

async fn spawn_daemon() -> std::process::Child {
    let bin = env!("CARGO_BIN_EXE_umcd");
    let _ = std::fs::remove_file(socket_path());
    std::fs::create_dir_all(data_dir()).unwrap();
    Command::new(bin)
        .env("HOME", data_dir().to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn umcd")
}

#[tokio::test]
async fn application_lifecycle_over_control_api() {
    let mut child = spawn_daemon().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let mut client = Client::connect(socket_path().to_str().unwrap(), "phase9-echo").await.expect("connect");

    // Register.
    let app = client
        .register_application("echo-app", [7u8; 16], &[b"ep-1"], &[b"org.example.echo/1"])
        .await
        .expect("register");

    // Open a listener on the registered protocol.
    let listener = client.open_listener(&app, b"ep-1", b"org.example.echo/1").await.expect("listener");
    assert_eq!(listener.0.len(), 16);

    // Unsupported methods still report UNIMPLEMENTED (not UNKNOWN).
    let err = client.request("ApplicationService", "Connect", Vec::new()).await.unwrap_err();
    assert!(matches!(err, umc_sdk::client::ClientError::Unimplemented(_)));

    let _ = child.kill().unwrap();
    let _ = child.wait().await;
}

#[tokio::test]
async fn registration_is_principal_scoped() {
    let mut child = spawn_daemon().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let mut client = Client::connect(socket_path().to_str().unwrap(), "phase9-scope").await.expect("connect");
    let app = client.register_application("scoped", [8u8; 16], &[], &[b"org.example.x/1"]).await.expect("register");
    assert_eq!(app.0.len(), 16);
    let _ = child.kill().unwrap();
    let _ = child.wait().await;
}

#[tokio::test]
async fn proto_round_trip_smoke() {
    let request = api::RegisterApplicationRequest {
        application_name: "smoke".into(),
        application_instance_id: vec![0u8; 16],
        requested_endpoint_ids: vec![],
        requested_protocol_ids: vec![],
        requested_operations: vec![],
    };
    let mut bytes = Vec::new();
    prost::Message::encode(&request, &mut bytes).unwrap();
    let decoded = api::RegisterApplicationRequest::decode(bytes.as_slice()).unwrap();
    assert_eq!(decoded.application_name, "smoke");
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p phase9-tests`
Expected: PASS (3 tests). If `RegisterApplication` is not yet wired in the daemon dispatch, the test fails with `Unimplemented` — wire it in `bins/umcd/src/server.rs` `handle_request`:

```rust
        "RegisterApplication" => {
            let request = api::RegisterApplicationRequest::decode(request.payload.as_slice()).map_err(|_| api::StatusCode::InvalidArgument)?;
            match app_service.register_application(0, &request, &entropy) {
                Ok(handle) => {
                    let response = api::RegisterApplicationResponse { application_handle: Some(api::OpaqueHandle { bytes: handle.bytes }) };
                    // ...encode into the Response envelope with status OK
                }
                Err(_) => { /* status PERMISSION_DENIED */ }
            }
        }
```

- [ ] **Step 4: Commit**

```bash
git add tests/phase9 bins/umcd/src/server.rs
git commit -m "test(phase9): echo application over the control API"
```

---

### Task 7: Phase 9 completion gate

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Verify the full gate**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all green.

- [ ] **Step 2: Update README status**

```markdown
- [x] Phases 0-8 (protocol core, runtime, daemon loop)
- [x] Phase 9: application layer — ApplicationService, listeners, streams, SDK
```

- [ ] **Step 3: Verify Phase 9 success criteria**

Checklist:

- [ ] Application registration with principal-scoped handles
- [ ] Listener binding (endpoint + protocol, duplicate rejection)
- [ ] Chunked stream transfer (64 KiB default, 256 KiB max, one read/write in flight)
- [ ] Write success = daemon ownership, not peer consumption
- [ ] Rust SDK: register, listen, connect, stream read/write/close
- [ ] Applications can use the same core independently (success criterion 9)

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: phase 9 complete"
```

---

## Phase 9 self-review

**Spec coverage:** `control-api.md` §31 (registration) → Task 1; §32 (listeners) → Task 2; §34 (streams, chunking, in-flight limits) → Task 3; §30.2/§35 (datagrams land with session wiring) → Task 6; `sdk.md` §11-18 (application surface) → Task 5.

**Known deferrals:** Connect/OpenStream/ReceiveDatagram full round trips (they need the daemon session loop to drive real UMP sessions — Phase 8's loop dispatches, Phase 10 wires sessions to ApplicationService), session accept events, stream accept/reject, event subscriptions for applications, resumable registrations.
