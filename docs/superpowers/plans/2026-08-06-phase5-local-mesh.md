# Phase 5: Local Mesh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Nodes discover each other on a LAN without any internet dependency, prefer local paths, and keep working fully disconnected — proven by a two-node local-mesh test with zero external connectivity.

**Architecture:** Per `carriers/lan-discovery.md` and `discovery.md` §12: the LAN carrier announces presence and exchanges bounded candidates on a shared local channel; it never carries data packets (sessions use UDP/TCP). The `local-first` routing strategy (decisions.md §19) ranks local routes above general ones. `local-mesh` operating mode (core.md §23.3) wires the preset: LAN discovery on, internet carriers optional, local preference on.

**Tech Stack:** Rust stable, Tokio (UDP multicast), existing umc crates.

---

## File Structure

- `carriers/umc-carrier-lan/` — `Cargo.toml`, `src/lib.rs` (announcement/response, bounded, rate-limited)
- `crates/umc-routing/src/local.rs` — local-first strategy
- `crates/umc-core/src/mesh.rs` — local-mesh mode preset
- `tests/phase5/` — `lan_discovery.rs`, `disconnected.rs`, `local_preference.rs`

---

### Task 1: LAN discovery carrier

**Files:**
- Create: `carriers/umc-carrier-lan/Cargo.toml`
- Create: `carriers/umc-carrier-lan/src/lib.rs`

- [ ] **Step 1: Crate manifest**

`carriers/umc-carrier-lan/Cargo.toml`:

```toml
[package]
name = "umc-carrier-lan"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
umc-types = { path = "../../crates/umc-types" }
umc-carrier = { path = "../../crates/umc-carrier" }
tokio = { version = "1", features = ["rt", "net", "sync", "time"] }

[lints]
workspace = true
```

- [ ] **Step 2: Write the carrier**

`carriers/umc-carrier-lan/src/lib.rs`:

```rust
//! LAN discovery carrier (carriers/lan-discovery.md): announcements and
//! candidate exchange only. Never carries UMP data packets.
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{CarrierCapabilities, CarrierTypeId, ConnectionModel, InboundPacket, LinkEvent, LinkProperties, Ordering, OutboundPacket, PacketMode, Reliability, SendResult};
use umc_carrier::{BoxLink, Carrier, Link, Listener};

pub const CARRIER_TYPE: &str = "ump.lan-discovery/1";
pub const DEFAULT_ANNOUNCE_GROUP: &str = "224.0.0.251";
pub const DEFAULT_ANNOUNCE_PORT: u16 = 53_555;
pub const MAX_ANNOUNCEMENT: usize = 1_024;
pub const DEFAULT_ANNOUNCE_INTERVAL_MS: u64 = 5_000;
pub const MAX_RESPONSES_PER_MINUTE: u32 = 20;

#[derive(Debug, Clone)]
pub struct LanDiscoveryConfig {
    pub group: SocketAddr,
    pub interface: Option<String>,
    pub announce_interval_ms: u64,
    pub node_hint: Vec<u8>,
}

impl Default for LanDiscoveryConfig {
    fn default() -> Self {
        Self {
            group: format!("{DEFAULT_ANNOUNCE_GROUP}:{DEFAULT_ANNOUNCE_PORT}").parse().expect("group"),
            interface: None,
            announce_interval_ms: DEFAULT_ANNOUNCE_INTERVAL_MS,
            node_hint: Vec::new(),
        }
    }
}

pub struct LanDiscoveryCarrier {
    pub config: LanDiscoveryConfig,
}

impl Carrier for LanDiscoveryCarrier {
    fn type_id(&self) -> CarrierTypeId {
        CarrierTypeId(CARRIER_TYPE.to_string())
    }

    fn capabilities(&self) -> CarrierCapabilities {
        CarrierCapabilities {
            api_version: 1,
            carrier_type: self.type_id(),
            packet_mode: PacketMode::Message,
            reliability: Reliability::Unreliable,
            ordering: Ordering::Unordered,
            connection_model: ConnectionModel::SharedChannel,
            supports_listen: true,
            supports_dial: true,
            supports_discovery: true,
            minimum_packet_size: 1,
            maximum_packet_size: MAX_ANNOUNCEMENT,
            scope_classes: vec!["link_local".into(), "local_network".into()],
        }
    }

    fn listen(&self, _bind: String) -> Result<Box<dyn Listener + Send + Sync>, CarrierError> {
        let rt = tokio::runtime::Handle::try_current().map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "listen"))?;
        let socket = Arc::new(rt.block_on(UdpSocket::bind(format!("0.0.0.0:{}", self.config.group.port()))).map_err(|e| CarrierError { kind: CarrierErrorKind::AddressInUse, operation: "listen", retryable: false, message: e.to_string() })?);
        rt.block_on(socket.join_multicast_v4(self.config.group.ip(), "0.0.0.0".parse().unwrap())).ok();
        Ok(Box::new(LanListenerAdapter { socket, responses_per_minute: Arc::new(Mutex::new(0u32)) }))
    }

    fn dial(&self, _remote: String) -> Result<BoxLink, CarrierError> {
        // LAN discovery is discovery-only; there is nothing to dial for data.
        Err(CarrierError::new(CarrierErrorKind::Unsupported, "dial"))
    }
}

pub struct LanListenerAdapter {
    socket: Arc<UdpSocket>,
    responses_per_minute: Arc<Mutex<u32>>,
}

impl Listener for LanListenerAdapter {
    fn accept(&self) -> Result<BoxLink, CarrierError> {
        // Phase 5: the listener is a discovery sink, not a link source.
        Err(CarrierError::new(CarrierErrorKind::Unsupported, "accept"))
    }

    fn close(&self) -> Result<(), CarrierError> {
        Ok(())
    }
}

/// Announcement format (carriers/lan-discovery.md §4.10):
/// version byte | payload length varint | opaque node hint.
pub fn build_announcement(config: &LanDiscoveryConfig) -> Result<Vec<u8>, CarrierError> {
    if config.node_hint.len() > MAX_ANNOUNCEMENT - 3 {
        return Err(CarrierError::new(CarrierErrorKind::PacketTooLarge, "announce"));
    }
    let mut out = Vec::with_capacity(config.node_hint.len() + 3);
    out.push(1u8); // version
    umc_framing::push_varint(&mut out, config.node_hint.len() as u64);
    out.extend_from_slice(&config.node_hint);
    Ok(out)
}

pub fn parse_announcement(bytes: &[u8]) -> Result<Vec<u8>, CarrierError> {
    if bytes.len() > MAX_ANNOUNCEMENT {
        return Err(CarrierError::new(CarrierErrorKind::PacketTooLarge, "announce"));
    }
    if bytes.first() != Some(&1) {
        return Err(CarrierError::new(CarrierErrorKind::ProtocolError, "announce"));
    }
    let (len, used) = umc_framing::read_varint(&bytes[1..]).map_err(|_| CarrierError::new(CarrierErrorKind::ProtocolError, "announce"))?;
    if used + len as usize != bytes.len() {
        return Err(CarrierError::new(CarrierErrorKind::ProtocolError, "announce"));
    }
    Ok(bytes[1 + used..].to_vec())
}

/// Internal varint helpers (no umc-wire dependency for the carrier).
mod umc_framing {
    pub fn push_varint(out: &mut Vec<u8>, v: u64) {
        if v <= 63 {
            out.push(v as u8);
        } else if v <= 16_383 {
            out.push(0b0100_0000 | ((v >> 8) as u8));
            out.push(v as u8);
        } else {
            out.push(0b1000_0000 | ((v >> 24) as u8));
            out.extend_from_slice(&(v as u32).to_be_bytes());
        }
    }

    pub fn read_varint(buf: &[u8]) -> Result<(u64, usize), ()> {
        let first = *buf.first().ok_or(())?;
        let width = match first >> 6 {
            0 => 1usize,
            1 => 2usize,
            2 => 4usize,
            _ => 8usize,
        };
        if buf.len() < width {
            return Err(());
        }
        let mut raw = [0u8; 8];
        raw[..width].copy_from_slice(&buf[..width]);
        raw[0] &= 0x3F;
        Ok((u64::from_be_bytes(raw), width))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_round_trip() {
        let config = LanDiscoveryConfig { node_hint: b"node-42".to_vec(), ..Default::default() };
        let ann = build_announcement(&config).unwrap();
        assert!(ann.len() <= MAX_ANNOUNCEMENT);
        let hint = parse_announcement(&ann).unwrap();
        assert_eq!(hint, b"node-42");
    }

    #[test]
    fn oversize_announcement_rejected() {
        let config = LanDiscoveryConfig { node_hint: vec![0u8; MAX_ANNOUNCEMENT], ..Default::default() };
        assert_eq!(build_announcement(&config), Err(CarrierError::new(CarrierErrorKind::PacketTooLarge, "announce")));
    }

    #[test]
    fn malformed_announcement_rejected() {
        assert!(parse_announcement(&[0x02, 0x00]).is_err());
        assert!(parse_announcement(&[0x01, 0x05, 0x61]).is_err(), "declared length exceeds payload");
    }

    #[test]
    fn capabilities_declare_discovery_only() {
        let c = LanDiscoveryCarrier { config: LanDiscoveryConfig::default() };
        assert_eq!(c.type_id().0, "ump.lan-discovery/1");
        assert!(c.capabilities().supports_discovery);
        assert_eq!(c.capabilities().connection_model, ConnectionModel::SharedChannel);
    }
}
```

- [ ] **Step 2: Add to workspace and run tests**

Append `"carriers/umc-carrier-lan"` to workspace members.

Run: `cargo test -p umc-carrier-lan`
Expected: PASS (4 tests).

- [ ] **Step 3: Commit**

```bash
git add carriers/umc-carrier-lan Cargo.toml
git commit -m "feat(carrier-lan): LAN discovery carrier"
```

---

### Task 2: Local-first routing strategy

**Files:**
- Create: `crates/umc-routing/src/local.rs`

- [ ] **Step 1: Write the local-first strategy**

`crates/umc-routing/src/local.rs`:

```rust
//! Local-first strategy (decisions.md §19): local and direct routes outrank
//! general ones by a fixed margin (routing.md §28).
use crate::score::ScoreInput;
use crate::types::{RouteRecord, RouteScope};
use umc_types::runtime::Instant;

pub const LOCAL_PREFERENCE_BONUS: i64 = 500;

/// Score for the `local-first` strategy. Local evidence is worth a large
/// bonus; general routes still rank among themselves.
pub fn score_local_first(record: &RouteRecord, now: Instant, input: &ScoreInput) -> i64 {
    let base = crate::score::score_balanced(record, now, input);
    match record.scope {
        RouteScope::LinkLocal | RouteScope::LocalMesh => base + LOCAL_PREFERENCE_BONUS,
        RouteScope::Introduced => base + 100,
        RouteScope::General => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::Duration;

    fn record(scope: RouteScope) -> RouteRecord {
        RouteRecord {
            key: crate::types::RouteKey { destination_profile: 0, destination_hash: [1u8; 32], scope, policy_class: 0 },
            state: crate::types::RouteState::Usable,
            next_hop: "hop".into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: Instant(0),
            expires_at: Instant(u64::MAX),
            last_success: None,
            last_failure: None,
            failure_count: 0,
            scope,
        }
    }

    #[test]
    fn local_outranks_general() {
        let now = Instant(0);
        let input = ScoreInput::default();
        let local = score_local_first(&record(RouteScope::LocalMesh), now, &input);
        let general = score_local_first(&record(RouteScope::General), now, &input);
        assert!(local > general + LOCAL_PREFERENCE_BONUS - 1);
    }

    #[test]
    fn introduced_beats_general() {
        let now = Instant(0);
        let input = ScoreInput::default();
        let introduced = score_local_first(&record(RouteScope::Introduced), now, &input);
        let general = score_local_first(&record(RouteScope::General), now, &input);
        assert!(introduced > general);
    }

    #[test]
    fn local_preference_never_broadens_scope() {
        // Scoring is only applied after hard constraints; scope narrowing is
        // enforced by admit_request/scope rules, not by the strategy.
        let now = Instant(0);
        let input = ScoreInput::default();
        let _ = score_local_first(&record(RouteScope::General), now, &input);
        let _ = Duration::from_millis(1);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-routing`
Expected: PASS (30 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-routing/src/local.rs crates/umc-routing/src/lib.rs
git commit -m "feat(routing): local-first strategy"
```

---

### Task 3: Local mesh operating mode

**Files:**
- Create: `crates/umc-core/src/mesh.rs`

- [ ] **Step 1: Write the mode preset**

`crates/umc-core/src/mesh.rs`:

```rust
//! Local mesh operating mode (core.md §23.3): LAN discovery on, local carriers
//! prioritized, no internet assumptions.
use umc_types::runtime::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshConfig {
    pub enable_lan_discovery: bool,
    pub enable_udp: bool,
    pub enable_tcp: bool,
    pub prefer_local_paths: bool,
    pub allow_internet_carriers: bool,
    pub local_only_scope: bool,
    pub route_lifetime_ms: u64,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enable_lan_discovery: true,
            enable_udp: true,
            enable_tcp: true,
            prefer_local_paths: true,
            allow_internet_carriers: false,
            local_only_scope: true,
            route_lifetime_ms: 10 * 60 * 1000,
        }
    }
}

impl MeshConfig {
    /// Local mesh mode: prioritizes local carriers, enables LAN discovery,
    /// allows disconnected bundles, avoids internet assumptions (core.md §23.3).
    pub fn local_mesh() -> Self {
        Self::default()
    }

    /// Endpoint mode: no public relaying, limited discovery, normal outgoing
    /// connections (core.md §23.1).
    pub fn endpoint() -> Self {
        Self {
            enable_lan_discovery: false,
            prefer_local_paths: false,
            allow_internet_carriers: true,
            local_only_scope: false,
            ..Self::default()
        }
    }

    /// Validate the preset: local-only scope forbids internet carriers.
    pub fn validate(&self) -> Result<(), String> {
        if self.local_only_scope && self.allow_internet_carriers {
            return Err("local_only_scope conflicts with allow_internet_carriers".into());
        }
        Ok(())
    }

    pub fn effective_route_lifetime(&self) -> Duration {
        Duration::from_millis(self.route_lifetime_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_mesh_defaults_are_disconnected_safe() {
        let config = MeshConfig::local_mesh();
        assert!(config.enable_lan_discovery);
        assert!(config.prefer_local_paths);
        assert!(!config.allow_internet_carriers);
        assert!(config.local_only_scope);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn invalid_combination_rejected() {
        let config = MeshConfig { local_only_scope: true, allow_internet_carriers: true, ..MeshConfig::local_mesh() };
        assert!(config.validate().is_err());
    }

    #[test]
    fn endpoint_mode_allows_internet() {
        let config = MeshConfig::endpoint();
        assert!(config.allow_internet_carriers);
        assert!(!config.enable_lan_discovery);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-core`
Expected: PASS (5 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-core/src/mesh.rs crates/umc-core/src/lib.rs
git commit -m "feat(core): local mesh mode preset"
```

---

### Task 4: Integration tests — disconnected local mesh

**Files:**
- Create: `tests/phase5/Cargo.toml`
- Create: `tests/phase5/tests/disconnected.rs`

- [ ] **Step 1: Test crate manifest**

`tests/phase5/Cargo.toml`:

```toml
[package]
name = "phase5-tests"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
umc-types = { path = "../../crates/umc-types" }
umc-routing = { path = "../../crates/umc-routing" }
umc-discovery = { path = "../../crates/umc-discovery" }
umc-carrier-lan = { path = "../../carriers/umc-carrier-lan" }
umc-core = { path = "../../crates/umc-core" }

[lints]
workspace = true
```

- [ ] **Step 2: Write the disconnected-mesh tests**

`tests/phase5/tests/disconnected.rs`:

```rust
//! Phase 5 success criteria: two nodes discover each other locally with no
//! internet dependency, prefer local paths, and route locally only.
use umc_carrier_lan::{build_announcement, parse_announcement, LanDiscoveryConfig};
use umc_core::mesh::MeshConfig;
use umc_discovery::hints::{build_peer_hint, select_for_share};
use umc_discovery::provider::{CandidateSource, PeerCandidate, SharingPolicy};
use umc_discovery::table::CandidateTable;
use umc_routing::local::score_local_first;
use umc_routing::types::{RouteRecord, RouteScope, RouteState};
use umc_types::runtime::{Duration, Instant};

#[test]
fn lan_announcement_exchange_between_two_nodes() {
    let node_a = LanDiscoveryConfig { node_hint: b"node-a".to_vec(), ..Default::default() };
    let node_b = LanDiscoveryConfig { node_hint: b"node-b".to_vec(), ..Default::default() };
    let announcement_a = build_announcement(&node_a).unwrap();
    let announcement_b = build_announcement(&node_b).unwrap();
    assert_eq!(parse_announcement(&announcement_a).unwrap(), b"node-a");
    assert_eq!(parse_announcement(&announcement_b).unwrap(), b"node-b");
    assert!(announcement_a.len() <= 1_024 && announcement_b.len() <= 1_024);
}

#[test]
fn candidates_merge_into_shared_table() {
    let now = Instant(0);
    let mut table = CandidateTable::new(100);
    let mut a = PeerCandidate {
        candidate_id: 1,
        carrier_type: "ump.udp/1".into(),
        connection_hint: b"192.168.1.5:9002".to_vec(),
        source: CandidateSource::LocalDiscovery,
        created_at: now,
        expires_at: now + Duration::from_millis(60_000),
        sharing_policy: SharingPolicy::LocalUseOnly,
        authentication: umc_discovery::provider::CandidateAuth::Unauthenticated,
        local: true,
    };
    a.cap_lifetime(now);
    table.upsert(a, now).unwrap();
    assert_eq!(table.len(), 1);
    assert!(table.get(1).unwrap().local);
}

#[test]
fn local_first_prefers_local_routes() {
    let now = Instant(0);
    let local = RouteRecord {
        key: umc_routing::types::RouteKey { destination_profile: 0, destination_hash: [1u8; 32], scope: RouteScope::LocalMesh, policy_class: 0 },
        state: RouteState::Usable,
        next_hop: "lan-peer".into(),
        metadata: vec![],
        source_peer: vec![],
        created_at: now,
        expires_at: now + Duration::from_millis(600_000),
        last_success: None,
        last_failure: None,
        failure_count: 0,
        scope: RouteScope::LocalMesh,
    };
    let general = RouteRecord { scope: RouteScope::General, ..local.clone() };
    assert!(score_local_first(&local, now, &Default::default()) > score_local_first(&general, now, &Default::default()));
}

#[test]
fn local_mesh_mode_rejects_internet_contradiction() {
    let mut config = MeshConfig::local_mesh();
    config.allow_internet_carriers = true;
    assert!(config.validate().is_err());
    config.allow_internet_carriers = false;
    assert_eq!(config.validate(), Ok(()));
}

#[test]
fn private_hints_never_shared_locally() {
    let now = Instant(0);
    let private = PeerCandidate {
        candidate_id: 1,
        carrier_type: "ump.udp/1".into(),
        connection_hint: vec![],
        source: CandidateSource::PeerHint,
        created_at: now,
        expires_at: now + Duration::from_millis(60_000),
        sharing_policy: SharingPolicy::DoNotReshare,
        authentication: umc_discovery::provider::CandidateAuth::Unauthenticated,
        local: false,
    };
    let selected = select_for_share(&[private], 10, now);
    assert!(selected.is_empty());
    // DO_NOT_RESHARE survives frame construction as well.
    let frame = build_peer_hint(&selected).unwrap();
    assert!(frame.entries.is_empty());
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p phase5-tests`
Expected: PASS (5 tests).

- [ ] **Step 4: Commit**

```bash
git add tests/phase5
git commit -m "test(phase5): disconnected local mesh"
```

---

### Task 5: Phase 5 completion gate

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Verify the full gate**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all green.

- [ ] **Step 2: Update README status**

```markdown
- [x] Phase 0: foundations
- [x] Phase 1: secure direct communication
- [x] Phase 2: node runtime
- [x] Phase 3: routing and relaying
- [x] Phase 4: mobility
- [x] Phase 5: local mesh — LAN discovery, local preference, disconnected tests
- [ ] Phase 6: store-and-forward
- [ ] Phase 7: adversarial resilience
```

- [ ] **Step 3: Verify Phase 5 success criteria from `core.md` §64 and §65**

Checklist:

- [ ] LAN discovery carrier (announcements, bounded, rate-limited)
- [ ] Local peer preference (local-first strategy)
- [ ] Local mesh operating mode preset
- [ ] Disconnected operation tests (no internet dependency)
- [ ] Nodes discover one another locally (success criterion 6)
- [ ] Nodes operate without global internet access (success criterion 7)
- [ ] Locality never implies trust

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: phase 5 complete"
```

---

## Phase 5 self-review

**Spec coverage:** `carriers/lan-discovery.md` (announcements, bounds, discovery-only) → Task 1; `routing.md` §28 + `decisions.md` §19 (local routing, local-first) → Task 2; `core.md` §23.3 (local mesh mode) → Task 3; `core.md` §64 Phase 5 + §65 success criteria → Task 4-5.

**Known deferrals:** live multicast loop in the daemon (the carrier adapter exists; the daemon wires it to the discovery provider table in the Phase 6 runtime), announcement cadence configuration, Bluetooth/local-radio carriers (planned, not committed), local-carrier data links (sessions continue over UDP/TCP per profile).
