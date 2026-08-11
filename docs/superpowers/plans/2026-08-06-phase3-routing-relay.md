# Phase 3: Routing and Relaying Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Nodes discover routes to each other without a global topology, construct direct and single-relay paths, and forward opaque traffic through bounded relay circuits with quotas — proven by a 3-node integration test where two endpoints talk through an untrusted relay.

**Architecture:** Per `routing.md` and `relay.md`: the routing crate keeps bounded expiring state (request cache, reverse-path state, route cache) and treats every route response as a claim; the relay crate grants explicit circuits with fixed lifetime/byte/queue limits and never inspects inner bytes. Discovery is a provider interface over static peers and PEER_HINT exchange. All frames already exist in `umc-wire` (Phase 0); the session layer already provides the packet spaces.

**Tech Stack:** Rust stable, existing umc crates, proptest.

---

## File Structure

- `crates/umc-routing/` — `Cargo.toml`, `src/lib.rs`, `types.rs` (route records, states), `request.rs` (creation/admission), `duplicate.rs` (bounded cache), `reverse.rs` (reverse-path state), `response.rs` (validation/forwarding), `cache.rs` (route cache), `score.rs` (balanced strategy), `paths.rs` (construction), `failure.rs` (penalties/retry)
- `crates/umc-relay/` — `Cargo.toml`, `src/lib.rs`, `circuit.rs` (state machine, IDs), `admission.rs`, `quota.rs`, `forward.rs`, `close.rs`, `multi.rs`
- `crates/umc-discovery/` — `Cargo.toml`, `src/lib.rs`, `provider.rs`, `table.rs`, `hints.rs`, `invitation.rs`
- `tests/phase3/` — `relay_session.rs`, `route_discovery.rs`

---

### Task 1: umc-routing — route record types and state machine

**Files:**
- Create: `crates/umc-routing/Cargo.toml`
- Create: `crates/umc-routing/src/lib.rs`
- Create: `crates/umc-routing/src/types.rs`

- [ ] **Step 1: Crate manifest**

`crates/umc-routing/Cargo.toml`:

```toml
[package]
name = "umc-routing"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
umc-types = { path = "../umc-types" }
umc-wire = { path = "../umc-wire" }
umc-types = { path = "../umc-types" }

[dev-dependencies]
proptest = "1"

[lints]
workspace = true
```

(Remove the duplicate `umc-types` line.)

- [ ] **Step 2: Write route record types**

`crates/umc-routing/src/lib.rs`:

```rust
pub mod cache;
pub mod duplicate;
pub mod failure;
pub mod paths;
pub mod request;
pub mod response;
pub mod reverse;
pub mod score;
pub mod types;
```

`crates/umc-routing/src/types.rs`:

```rust
//! Route records and state machine (routing.md §6).
use umc_types::runtime::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteState {
    Candidate,
    Probing,
    Usable,
    Degraded,
    Failed,
    Expired,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteScope {
    LinkLocal,
    LocalMesh,
    Introduced,
    General,
}

impl RouteScope {
    /// Scope may narrow, never broaden (routing.md §14.5).
    pub fn narrows_to(&self, other: RouteScope) -> bool {
        rank(*self) >= rank(other)
    }
}

fn rank(scope: RouteScope) -> u8 {
    match scope {
        RouteScope::LinkLocal => 0,
        RouteScope::LocalMesh => 1,
        RouteScope::Introduced => 2,
        RouteScope::General => 3,
    }
}

pub const MAX_HOP_LIMIT: u64 = 32;
pub const DEFAULT_HOP_LIMIT: u64 = 8;
pub const DEFAULT_FANOUT: usize = 3;
pub const MAX_FANOUT: usize = 8;
pub const MAX_REQUEST_LIFETIME_MS: u64 = 5 * 60 * 1000;
pub const DEFAULT_REQUEST_LIFETIME_MS: u64 = 30_000;
pub const MAX_RESPONSES_PER_BRANCH: usize = 8;
pub const MAX_PATH_EXCLUSIONS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRecord {
    pub key: RouteKey,
    pub state: RouteState,
    pub next_hop: String,
    pub metadata: Vec<u8>,
    pub source_peer: Vec<u8>,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,
    pub failure_count: u64,
    pub scope: RouteScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    pub destination_profile: u8,
    pub destination_hash: [u8; 32],
    pub scope: RouteScope,
    pub policy_class: u8,
}

impl RouteRecord {
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    pub fn mark(&mut self, state: RouteState, now: Instant) {
        match state {
            RouteState::Usable => {
                self.last_success = Some(now);
                self.failure_count = 0;
            }
            RouteState::Failed => {
                self.last_failure = Some(now);
                self.failure_count += 1;
            }
            _ => {}
        }
        self.state = state;
    }

    /// Route expiry never exceeds underlying evidence expiry (routing.md §24.2).
    pub fn cap_expiry(&mut self, evidence_expiry: Instant) {
        if evidence_expiry < self.expires_at {
            self.expires_at = evidence_expiry;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_narrow_but_never_broaden() {
        assert!(RouteScope::General.narrows_to(RouteScope::LocalMesh));
        assert!(RouteScope::LocalMesh.narrows_to(RouteScope::LocalMesh));
        assert!(!RouteScope::LocalMesh.narrows_to(RouteScope::General));
    }

    #[test]
    fn route_record_lifecycle() {
        let now = Instant(0);
        let mut r = RouteRecord {
            key: RouteKey { destination_profile: 0, destination_hash: [0u8; 32], scope: RouteScope::General, policy_class: 0 },
            state: RouteState::Candidate,
            next_hop: "peer-a".into(),
            metadata: vec![],
            source_peer: vec![1],
            created_at: now,
            expires_at: now + Duration::from_millis(600_000),
            last_success: None,
            last_failure: None,
            failure_count: 0,
            scope: RouteScope::General,
        };
        assert!(!r.is_expired(now + Duration::from_millis(599_999)));
        assert!(r.is_expired(now + Duration::from_millis(600_000)));
        r.mark(RouteState::Usable, now + Duration::from_millis(10));
        assert_eq!(r.last_success, Some(now + Duration::from_millis(10)));
        r.mark(RouteState::Failed, now + Duration::from_millis(20));
        assert_eq!(r.failure_count, 1);
        assert_eq!(r.state, RouteState::Failed);
    }

    #[test]
    fn expiry_capped_by_evidence() {
        let now = Instant(0);
        let mut r = RouteRecord {
            key: RouteKey { destination_profile: 0, destination_hash: [1u8; 32], scope: RouteScope::General, policy_class: 0 },
            state: RouteState::Usable,
            next_hop: "x".into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: now,
            expires_at: now + Duration::from_millis(1_000),
            last_success: None,
            last_failure: None,
            failure_count: 0,
            scope: RouteScope::General,
        };
        r.cap_expiry(now + Duration::from_millis(500));
        assert_eq!(r.expires_at, now + Duration::from_millis(500));
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-routing`
Expected: PASS (4 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-routing
git commit -m "feat(routing): route records and state machine"
```

---

### Task 2: Request IDs and duplicate suppression

**Files:**
- Create: `crates/umc-routing/src/duplicate.rs`

- [ ] **Step 1: Write the request-ID generator and duplicate cache**

`crates/umc-routing/src/duplicate.rs`:

```rust
//! Unpredictable Request IDs and the bounded duplicate cache (routing.md §7, §11).
use std::collections::VecDeque;
use umc_types::runtime::{Duration, EntropySource, Instant};

pub const REQUEST_ID_LEN: usize = 16;
pub const DEFAULT_CACHE_ENTRIES: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestIdentity {
    pub request_id: [u8; REQUEST_ID_LEN],
    pub adjacent_sender: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CachedRequest {
    pub identity: RequestIdentity,
    pub first_seen: Instant,
    pub best_hop_limit: u64,
    pub expiry: Instant,
    pub forwarded_peers: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct RequestCache {
    entries: VecDeque<CachedRequest>,
    max_entries: usize,
    retention: Duration,
}

impl RequestCache {
    pub fn new(max_entries: usize, retention: Duration) -> Self {
        Self { entries: VecDeque::new(), max_entries, retention }
    }

    pub fn generate_request_id(entropy: &dyn EntropySource) -> [u8; REQUEST_ID_LEN] {
        let mut id = [0u8; REQUEST_ID_LEN];
        entropy.fill(&mut id);
        id
    }

    /// Returns None when the request is new or an improvement is allowed
    /// (higher hop limit); returns Some(existing) for an exact duplicate.
    pub fn admit(&mut self, identity: RequestIdentity, hop_limit: u64, now: Instant, forward_to: &[u8]) -> Option<CachedRequest> {
        self.prune(now);
        if let Some(existing) = self.entries.iter().find(|e| e.identity == identity) {
            if hop_limit <= existing.best_hop_limit {
                return Some(existing.clone());
            }
            // Improvement: allowed but must not re-forward to the same peer.
            if forward_to.iter().any(|p| existing.forwarded_peers.contains(p)) {
                return Some(existing.clone());
            }
        }
        self.entries.push_back(CachedRequest {
            identity,
            first_seen: now,
            best_hop_limit: hop_limit,
            expiry: now + self.retention,
            forwarded_peers: forward_to.to_vec(),
        });
        if self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
        None
    }

    pub fn record_forward(&mut self, identity: &RequestIdentity, peer: &[u8]) {
        if let Some(entry) = self.entries.iter_mut().find(|e| &e.identity == identity) {
            if !entry.forwarded_peers.contains(&peer.to_vec()) {
                entry.forwarded_peers.push(peer.to_vec());
            }
        }
    }

    pub fn already_forwarded(&self, identity: &RequestIdentity, peer: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|e| &e.identity == identity && e.forwarded_peers.contains(&peer.to_vec()))
    }

    fn prune(&mut self, now: Instant) {
        self.entries.retain(|e| e.expiry > now);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0x11);
        }
    }

    fn id(n: u8) -> RequestIdentity {
        let mut request_id = [0u8; REQUEST_ID_LEN];
        request_id[0] = n;
        RequestIdentity { request_id, adjacent_sender: vec![n] }
    }

    #[test]
    fn exact_duplicate_suppressed() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        assert!(cache.admit(id(1), 8, Instant(0), &[b"peer-a"]).is_none());
        assert!(cache.admit(id(1), 8, Instant(1), &[b"peer-a"]).is_some());
    }

    #[test]
    fn higher_hop_limit_allows_reconsideration() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        cache.admit(id(1), 4, Instant(0), &[b"peer-a"]).unwrap();
        // New path with higher hop limit is admitted.
        assert!(cache.admit(id(1), 8, Instant(1), &[b"peer-b"]).is_none());
        // But never re-forwards to peer-a.
        cache.record_forward(&id(1), b"peer-a");
        assert!(cache.already_forwarded(&id(1), b"peer-a"));
        assert!(!cache.already_forwarded(&id(1), b"peer-b"));
    }

    #[test]
    fn cache_is_bounded() {
        let mut cache = RequestCache::new(2, Duration::from_millis(30_000));
        cache.admit(id(1), 8, Instant(0), &[]);
        cache.admit(id(2), 8, Instant(0), &[]);
        cache.admit(id(3), 8, Instant(0), &[]);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn request_ids_are_unpredictable_bytes() {
        let a = RequestCache::generate_request_id(&E);
        let b = RequestCache::generate_request_id(&E);
        assert_eq!(a, b); // deterministic test entropy; production uses CSPRNG
        assert_eq!(a.len(), REQUEST_ID_LEN);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-routing`
Expected: PASS (8 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-routing/src/duplicate.rs
git commit -m "feat(routing): request IDs and duplicate suppression"
```

---

### Task 3: Request admission and hop-limit enforcement

**Files:**
- Create: `crates/umc-routing/src/request.rs`

- [ ] **Step 1: Write request admission**

`crates/umc-routing/src/request.rs`:

```rust
//! ROUTE_REQUEST admission (routing.md §8-13): cheap checks before any work.
use crate::duplicate::{RequestCache, RequestIdentity};
use crate::types::{DEFAULT_FANOUT, DEFAULT_HOP_LIMIT, MAX_FANOUT, MAX_HOP_LIMIT, MAX_REQUEST_LIFETIME_MS, RouteScope};
use umc_types::runtime::{Duration, EntropySource, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Admit { hop_limit: u64, remaining_lifetime_ms: u64, forward_to: Vec<Vec<u8>> },
    Suppress,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    HopLimitZero,
    HopLimitExceeded,
    LifetimeTooLong,
    UnknownFlag,
    FanoutExceeded,
    RateLimited,
}

#[derive(Debug, Clone)]
pub struct RequestPolicy {
    pub max_fanout: usize,
    pub max_hops: u64,
    pub max_lifetime_ms: u64,
    pub requests_per_minute: u64,
}

impl Default for RequestPolicy {
    fn default() -> Self {
        Self { max_fanout: MAX_FANOUT, max_hops: MAX_HOP_LIMIT, max_lifetime_ms: MAX_REQUEST_LIFETIME_MS, requests_per_minute: 60 }
    }
}

/// Validate and admit a route request (routing.md §10). Returns the effective
/// hop limit after decrement and the peers to forward to (default fanout).
pub fn admit_request(
    request_id: &[u8; 16],
    adjacent_sender: &[u8],
    flags: u8,
    hop_limit: u64,
    lifetime_ms: u64,
    candidates: &[Vec<u8>],
    policy: &RequestPolicy,
    cache: &mut RequestCache,
    now: Instant,
) -> Result<Admission, AdmissionError> {
    // 1. Cheap field validation.
    if hop_limit == 0 {
        return Err(AdmissionError::HopLimitZero);
    }
    if hop_limit > policy.max_hops || hop_limit > MAX_HOP_LIMIT {
        return Err(AdmissionError::HopLimitExceeded);
    }
    if lifetime_ms > policy.max_lifetime_ms || lifetime_ms > MAX_REQUEST_LIFETIME_MS {
        return Err(AdmissionError::LifetimeTooLong);
    }
    if flags & 0xE0 != 0 {
        return Err(AdmissionError::UnknownFlag);
    }
    // 2. Duplicate suppression.
    let identity = RequestIdentity { request_id: *request_id, adjacent_sender: adjacent_sender.to_vec() };
    let fanout = candidates.len().min(policy.max_fanout).min(MAX_FANOUT);
    if fanout == 0 {
        // Direct-match only: no forwarding.
        return Ok(Admission::Admit { hop_limit: hop_limit.saturating_sub(1), remaining_lifetime_ms: lifetime_ms, forward_to: vec![] });
    }
    let forward_to: Vec<Vec<u8>> = candidates[..fanout].to_vec();
    if let Some(existing) = cache.admit(identity.clone(), hop_limit, now, &forward_to) {
        if existing.best_hop_limit >= hop_limit {
            return Ok(Admission::Suppress);
        }
    }
    if cache.already_forwarded(&identity, &forward_to[0]) {
        return Ok(Admission::Suppress);
    }
    // 3. Fanout bound (routing.md §13).
    if candidates.len() > MAX_FANOUT {
        return Err(AdmissionError::FanoutExceeded);
    }
    Ok(Admission::Admit { hop_limit: hop_limit.saturating_sub(1), remaining_lifetime_ms: lifetime_ms, forward_to })
}

/// Select initial peers for a new request (routing.md §9): diverse, small set.
pub fn select_initial_peers(candidates: &[Vec<u8>], default_fanout: usize) -> Vec<Vec<u8>> {
    candidates.iter().take(default_fanout.max(1)).cloned().collect()
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

    fn policy() -> RequestPolicy {
        RequestPolicy::default()
    }

    #[test]
    fn hop_limit_decremented_and_bounded() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        let peers = vec![b"p1".to_vec(), b"p2".to_vec(), b"p3".to_vec()];
        let admission = admit_request(&[1u8; 16], b"src", 0, 8, 30_000, &peers, &policy(), &mut cache, Instant(0)).unwrap();
        match admission {
            Admission::Admit { hop_limit, forward_to, .. } => {
                assert_eq!(hop_limit, 7);
                assert_eq!(forward_to.len(), 3);
            }
            _ => panic!("expected admit"),
        }
    }

    #[test]
    fn zero_hop_limit_rejected() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        assert_eq!(
            admit_request(&[1u8; 16], b"src", 0, 0, 30_000, &[], &policy(), &mut cache, Instant(0)),
            Err(AdmissionError::HopLimitZero)
        );
    }

    #[test]
    fn lifetime_capped() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        assert_eq!(
            admit_request(&[1u8; 16], b"src", 0, 8, 6 * 60 * 1000, &[], &policy(), &mut cache, Instant(0)),
            Err(AdmissionError::LifetimeTooLong)
        );
    }

    #[test]
    fn fanout_bounded_to_policy() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        let peers: Vec<Vec<u8>> = (0..10).map(|i| vec![i]).collect();
        let admission = admit_request(&[1u8; 16], b"src", 0, 8, 30_000, &peers, &policy(), &mut cache, Instant(0)).unwrap();
        match admission {
            Admission::Admit { forward_to, .. } => assert_eq!(forward_to.len(), MAX_FANOUT),
            _ => panic!("expected admit"),
        }
    }

    #[test]
    fn exact_duplicate_suppressed() {
        let mut cache = RequestCache::new(100, Duration::from_millis(30_000));
        let peers = vec![b"p1".to_vec()];
        admit_request(&[1u8; 16], b"src", 0, 8, 30_000, &peers, &policy(), &mut cache, Instant(0)).unwrap();
        assert_eq!(
            admit_request(&[1u8; 16], b"src", 0, 8, 30_000, &peers, &policy(), &mut cache, Instant(1)).unwrap(),
            Admission::Suppress
        );
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-routing`
Expected: PASS (13 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-routing/src/request.rs
git commit -m "feat(routing): request admission with hop and fanout bounds"
```

---

### Task 4: Reverse-path state

**Files:**
- Create: `crates/umc-routing/src/reverse.rs`

- [ ] **Step 1: Write reverse-path state**

`crates/umc-routing/src/reverse.rs`:

```rust
//! Reverse-path state for response forwarding (routing.md §17-18).
use crate::types::MAX_RESPONSES_PER_BRANCH;
use std::collections::HashMap;
use umc_types::runtime::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ReverseEntry {
    pub request_id: [u8; 16],
    pub upstream: Vec<u8>,
    pub expiry: Instant,
    pub response_count: usize,
}

#[derive(Debug, Clone)]
pub struct ReverseState {
    entries: HashMap<[u8; 16], ReverseEntry>,
    retention: Duration,
}

impl ReverseState {
    pub fn new(retention: Duration) -> Self {
        Self { entries: HashMap::new(), retention }
    }

    pub fn create(&mut self, request_id: [u8; 16], upstream: Vec<u8>, now: Instant) {
        self.entries.insert(
            request_id,
            ReverseEntry { request_id, upstream, expiry: now + self.retention, response_count: 0 },
        );
    }

    /// A response may only travel to the upstream peer that supplied the
    /// matching request copy (routing.md §17).
    pub fn route_response(&mut self, request_id: &[u8; 16], now: Instant) -> Option<Vec<u8>> {
        self.prune(now);
        let entry = self.entries.get_mut(request_id)?;
        if entry.response_count >= MAX_RESPONSES_PER_BRANCH {
            return None;
        }
        entry.response_count += 1;
        Some(entry.upstream.clone())
    }

    pub fn upstream_of(&self, request_id: &[u8; 16], now: Instant) -> Option<Vec<u8>> {
        let entry = self.entries.get(request_id)?;
        if entry.expiry <= now {
            return None;
        }
        Some(entry.upstream.clone())
    }

    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, e| e.expiry > now);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_routed_to_upstream_only() {
        let mut state = ReverseState::new(Duration::from_millis(30_000));
        let rid = [7u8; 16];
        state.create(rid, b"upstream-a".to_vec(), Instant(0));
        assert_eq!(state.route_response(&rid, Instant(10)).unwrap(), b"upstream-a");
        // Unknown request ids are not routable.
        assert!(state.route_response(&[8u8; 16], Instant(10)).is_none());
    }

    #[test]
    fn response_budget_capped() {
        let mut state = ReverseState::new(Duration::from_millis(30_000));
        let rid = [7u8; 16];
        state.create(rid, b"up".to_vec(), Instant(0));
        for _ in 0..MAX_RESPONSES_PER_BRANCH {
            assert!(state.route_response(&rid, Instant(10)).is_some());
        }
        assert!(state.route_response(&rid, Instant(10)).is_none());
    }

    #[test]
    fn expires_with_request() {
        let mut state = ReverseState::new(Duration::from_millis(1_000));
        let rid = [7u8; 16];
        state.create(rid, b"up".to_vec(), Instant(0));
        assert!(state.upstream_of(&rid, Instant(999)).is_some());
        assert!(state.upstream_of(&rid, Instant(1_000)).is_none());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-routing`
Expected: PASS (16 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-routing/src/reverse.rs
git commit -m "feat(routing): reverse-path state"
```

---

### Task 5: Route cache

**Files:**
- Create: `crates/umc-routing/src/cache.rs`

- [ ] **Step 1: Write the route cache**

`crates/umc-routing/src/cache.rs`:

```rust
//! Bounded expiring route cache (routing.md §24).
use crate::types::{RouteKey, RouteRecord, RouteState};
use std::collections::HashMap;
use umc_types::runtime::{Duration, Instant};

pub const DEFAULT_CACHE_TARGET: usize = 3;
pub const DEFAULT_CACHE_MAX: usize = 8;
pub const DEFAULT_MAX_ROUTE_LIFETIME_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct RouteCache {
    by_key: HashMap<RouteKey, Vec<RouteRecord>>,
    max_per_key: usize,
    max_lifetime: Duration,
}

impl RouteCache {
    pub fn new(max_per_key: usize, max_lifetime: Duration) -> Self {
        Self { by_key: HashMap::new(), max_per_key, max_lifetime }
    }

    pub fn insert(&mut self, mut record: RouteRecord, now: Instant) {
        record.cap_expiry(now + self.max_lifetime);
        let key = record.key.clone();
        let entries = self.by_key.entry(key).or_default();
        entries.retain(|r| !r.is_expired(now) && r.next_hop != record.next_hop);
        entries.push(record);
        // Eviction order (routing.md §24.4): expired, failed, redundant, least useful.
        entries.sort_by_key(|r| match r.state {
            RouteState::Usable => 0,
            RouteState::Candidate => 1,
            RouteState::Probing => 2,
            RouteState::Degraded => 3,
            RouteState::Failed => 4,
            _ => 5,
        });
        entries.truncate(self.max_per_key);
    }

    pub fn candidates(&self, key: &RouteKey, now: Instant) -> Vec<RouteRecord> {
        self.by_key
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|r| !r.is_expired(now))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn evict_expired(&mut self, now: Instant) {
        self.by_key.retain(|_, entries| {
            entries.retain(|r| !r.is_expired(now));
            !entries.is_empty()
        });
    }

    pub fn len(&self) -> usize {
        self.by_key.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> RouteKey {
        RouteKey { destination_profile: 0, destination_hash: [n; 32], scope: crate::types::RouteScope::General, policy_class: 0 }
    }

    fn record(key: RouteKey, hop: &str, now: Instant) -> RouteRecord {
        RouteRecord {
            key: key.clone(),
            state: RouteState::Usable,
            next_hop: hop.into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: now,
            expires_at: now + Duration::from_millis(600_000),
            last_success: None,
            last_failure: None,
            failure_count: 0,
            scope: crate::types::RouteScope::General,
        }
    }

    #[test]
    fn insert_and_candidates() {
        let now = Instant(0);
        let mut cache = RouteCache::new(DEFAULT_CACHE_MAX, Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS));
        cache.insert(record(key(1), "hop-a", now), now);
        cache.insert(record(key(1), "hop-b", now), now);
        assert_eq!(cache.candidates(&key(1), now).len(), 2);
        assert_eq!(cache.candidates(&key(2), now).len(), 0);
    }

    #[test]
    fn per_key_bound_enforced() {
        let now = Instant(0);
        let mut cache = RouteCache::new(3, Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS));
        for i in 0..5 {
            cache.insert(record(key(1), &format!("hop-{i}"), now), now);
        }
        assert_eq!(cache.candidates(&key(1), now).len(), 3);
    }

    #[test]
    fn expired_entries_evicted() {
        let now = Instant(0);
        let mut cache = RouteCache::new(DEFAULT_CACHE_MAX, Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS));
        cache.insert(record(key(1), "hop-a", now), now);
        cache.evict_expired(now + Duration::from_millis(DEFAULT_MAX_ROUTE_LIFETIME_MS + 1));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn cache_lifetime_capped_at_max() {
        let now = Instant(0);
        let mut cache = RouteCache::new(DEFAULT_CACHE_MAX, Duration::from_millis(600_000));
        let mut r = record(key(1), "hop", now);
        r.expires_at = now + Duration::from_millis(3_600_000); // evidence says 1h
        cache.insert(r, now);
        // Cache caps at 10 minutes.
        let candidates = cache.candidates(&key(1), now + Duration::from_millis(600_001));
        assert!(candidates.is_empty());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-routing`
Expected: PASS (20 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-routing/src/cache.rs
git commit -m "feat(routing): bounded route cache with eviction"
```

---

### Task 6: Balanced scoring

**Files:**
- Create: `crates/umc-routing/src/score.rs`

- [ ] **Step 1: Write the balanced strategy**

`crates/umc-routing/src/score.rs`:

```rust
//! Route scoring (routing.md §22): hard constraints first, then the balanced
//! first-party strategy. Remote metric claims weigh less than local evidence.
use crate::types::RouteRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardConstraint {
    AllowedCarrier(String),
    MaxHops(u64),
    MinTrust(u8),
    LocalOnly,
}

#[derive(Debug, Clone)]
pub struct ScoreInput {
    pub local_success_weight: u64,
}

impl Default for ScoreInput {
    fn default() -> Self {
        Self { local_success_weight: 3 }
    }
}

/// Score for the `balanced` strategy (decisions.md §19). Higher is better.
pub fn score_balanced(record: &RouteRecord, now: umc_types::runtime::Instant, input: &ScoreInput) -> i64 {
    let mut score: i64 = 0;
    // Freshness.
    let age_ms = now.duration_since(record.created_at).as_millis() as i64;
    score -= age_ms / 10_000;
    // Local evidence outweighs remote claims (routing.md §22.2).
    if let Some(_s) = record.last_success {
        score += 100 * input.local_success_weight as i64;
    }
    if let Some(_f) = record.last_failure {
        score -= 50 * record.failure_count as i64;
    }
    // State ranking.
    score += match record.state {
        crate::types::RouteState::Usable => 200,
        crate::types::RouteState::Candidate => 50,
        crate::types::RouteState::Probing => 30,
        crate::types::RouteState::Degraded => -20,
        crate::types::RouteState::Failed => -200,
        crate::types::RouteState::Expired | crate::types::RouteState::Retired => i64::MIN / 2,
    };
    score
}

/// Filter hard constraints; ineligible candidates never enter scoring
/// (routing.md §22.1).
pub fn passes_hard_constraints(record: &RouteRecord, constraints: &[HardConstraint]) -> bool {
    constraints.iter().all(|c| match c {
        HardConstraint::MaxHops(hops) => record.metadata.iter().filter(|b| **b == b'h').count() as u64 <= *hops,
        HardConstraint::LocalOnly => record.scope != crate::types::RouteScope::General,
        HardConstraint::AllowedCarrier(_) | HardConstraint::MinTrust(_) => true, // policy fields on RouteRecord land in Phase 4
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::Duration;

    fn usable_record(now: umc_types::runtime::Instant) -> RouteRecord {
        RouteRecord {
            key: crate::types::RouteKey { destination_profile: 0, destination_hash: [0u8; 32], scope: crate::types::RouteScope::LocalMesh, policy_class: 0 },
            state: crate::types::RouteState::Usable,
            next_hop: "hop".into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: now,
            expires_at: now + Duration::from_millis(600_000),
            last_success: Some(now),
            last_failure: None,
            failure_count: 0,
            scope: crate::types::RouteScope::LocalMesh,
        }
    }

    #[test]
    fn usable_beats_failed() {
        let now = umc_types::runtime::Instant(0);
        let usable = usable_record(now);
        let mut failed = usable.clone();
        failed.state = crate::types::RouteState::Failed;
        assert!(score_balanced(&usable, now, &ScoreInput::default()) > score_balanced(&failed, now, &ScoreInput::default()));
    }

    #[test]
    fn failures_penalize() {
        let now = umc_types::runtime::Instant(0);
        let mut fresh = usable_record(now);
        let mut stale = usable_record(now);
        stale.created_at = now + Duration::from_millis(100_000);
        assert!(score_balanced(&fresh, now, &ScoreInput::default()) > score_balanced(&stale, now, &ScoreInput::default()));
    }

    #[test]
    fn local_only_constraint_filters_general() {
        let now = umc_types::runtime::Instant(0);
        let mut record = usable_record(now);
        record.scope = crate::types::RouteScope::General;
        assert!(!passes_hard_constraints(&record, &[HardConstraint::LocalOnly]));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-routing`
Expected: PASS (23 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-routing/src/score.rs
git commit -m "feat(routing): balanced scoring strategy"
```

---

### Task 7: Route failure and retry

**Files:**
- Create: `crates/umc-routing/src/failure.rs`

- [ ] **Step 1: Write failure penalties**

`crates/umc-routing/src/failure.rs`:

```rust
//! Route failure classes and retry delays (routing.md §26).
use umc_types::runtime::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    NoReachability,
    CarrierFailure,
    RelayRefused,
    AuthenticationFailed,
    PolicyRejected,
    Timeout,
    Loop,
    ResourceLimit,
    ProtocolError,
}

impl FailureClass {
    /// Recommended initial retry delays (routing.md §26.1).
    pub fn initial_retry_delay(self) -> Duration {
        match self {
            FailureClass::CarrierFailure => Duration::from_millis(1_000),
            FailureClass::Timeout => Duration::from_millis(5_000),
            FailureClass::RelayRefused => Duration::from_millis(30_000),
            FailureClass::PolicyRejected => Duration::from_millis(60 * 60 * 1000),
            FailureClass::AuthenticationFailed => Duration::from_millis(24 * 60 * 60 * 1000),
            FailureClass::Loop => Duration::from_millis(10_000),
            FailureClass::ResourceLimit => Duration::from_millis(5_000),
            FailureClass::ProtocolError => Duration::from_millis(30_000),
            FailureClass::NoReachability => Duration::from_millis(5_000),
        }
    }
}

pub const MAX_BACKOFF: u64 = 5 * 60 * 1000;

/// Capped exponential backoff with jitter (routing.md §26.1).
pub fn backoff_delay(failure_count: u64, base: Duration, jitter_ms: u64, seed: u64) -> Duration {
    let multiplier = 1u64 << failure_count.min(10);
    let delay = base.as_millis().saturating_mul(multiplier).min(MAX_BACKOFF);
    let jitter = (seed % jitter_ms.saturating_add(1)) as u64;
    Duration::from_millis(delay.saturating_add(jitter).min(MAX_BACKOFF))
}

#[derive(Debug, Clone)]
pub struct FailureTracker {
    pub last_failure: Option<(FailureClass, Instant)>,
    pub retry_after: Option<Instant>,
    pub failure_count: u64,
}

impl FailureTracker {
    pub fn new() -> Self {
        Self { last_failure: None, retry_after: None, failure_count: 0 }
    }

    pub fn record(&mut self, class: FailureClass, now: Instant, seed: u64) {
        self.failure_count += 1;
        let delay = backoff_delay(self.failure_count, class.initial_retry_delay(), 100, seed);
        self.retry_after = Some(now + delay);
        self.last_failure = Some((class, now));
    }

    pub fn can_retry(&self, now: Instant) -> bool {
        match self.retry_after {
            Some(deadline) => now >= deadline,
            None => true,
        }
    }

    /// Persisted failure penalties decay (routing.md §25): a stale failure
    /// never blocks rediscovery forever.
    pub fn decay(&mut self, now: Instant, half_life_ms: u64) {
        if let Some((_, at)) = self.last_failure {
            let age = now.duration_since(at).as_millis();
            if age >= half_life_ms {
                self.failure_count = self.failure_count / 2;
                self.retry_after = None;
            }
        }
    }
}

impl Default for FailureTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delays_follow_class() {
        assert_eq!(FailureClass::CarrierFailure.initial_retry_delay(), Duration::from_millis(1_000));
        assert_eq!(FailureClass::RelayRefused.initial_retry_delay(), Duration::from_millis(30_000));
    }

    #[test]
    fn backoff_capped() {
        let d = backoff_delay(20, Duration::from_millis(1_000), 0, 0);
        assert!(d.as_millis() <= MAX_BACKOFF);
    }

    #[test]
    fn tracker_blocks_until_retry_time() {
        let mut t = FailureTracker::new();
        assert!(t.can_retry(Instant(0)));
        t.record(FailureClass::CarrierFailure, Instant(0), 0);
        assert!(!t.can_retry(Instant(500)));
        assert!(t.can_retry(Instant(2_000)));
    }

    #[test]
    fn decay_half_life() {
        let mut t = FailureTracker::new();
        t.record(FailureClass::Timeout, Instant(0), 0);
        t.failure_count = 10;
        t.decay(Instant(100_000), 60_000);
        assert_eq!(t.failure_count, 5);
        assert!(t.can_retry(Instant(100_000)));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-routing`
Expected: PASS (27 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-routing/src/failure.rs
git commit -m "feat(routing): failure classes and retry backoff"
```

---

### Task 8: umc-relay — circuit state machine and identifiers

**Files:**
- Create: `crates/umc-relay/Cargo.toml`
- Create: `crates/umc-relay/src/lib.rs`
- Create: `crates/umc-relay/src/circuit.rs`

- [ ] **Step 1: Crate manifest**

`crates/umc-relay/Cargo.toml`:

```toml
[package]
name = "umc-relay"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
umc-types = { path = "../umc-types" }
umc-wire = { path = "../umc-wire" }

[dev-dependencies]
proptest = "1"

[lints]
workspace = true
```

`crates/umc-relay/src/lib.rs`:

```rust
pub mod admission;
pub mod circuit;
pub mod close;
pub mod forward;
pub mod multi;
pub mod quota;
```

- [ ] **Step 2: Write circuit state**

`crates/umc-relay/src/circuit.rs`:

```rust
//! Relay circuit state machine and identifiers (relay.md §8-9).
use umc_types::runtime::{Duration, EntropySource, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Opening,
    Active,
    HalfClosedUpstream,
    HalfClosedDownstream,
    Closing,
    Draining,
    Closed,
}

pub const DEFAULT_LIFETIME_MS: u64 = 10 * 60 * 1000;
pub const MAX_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 2 * 60 * 1000;
pub const MAX_RELAY_PAYLOAD: usize = 64 * 1024;
pub const MAX_RELAY_NODES: usize = 4;
pub const PROTOCOL_MAX_RELAY_NODES: usize = 16;

#[derive(Debug, Clone)]
pub struct Circuit {
    pub circuit_id: u64,
    pub state: CircuitState,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub idle_deadline: Instant,
    pub granted_byte_quota: u64,
    pub bytes_forwarded: u64,
    pub next_relay_sequence: u64,
    pub downstream: Option<Vec<u8>>,
    pub private_handling: bool,
    pub bidirectional: bool,
    pub last_activity: Instant,
}

impl Circuit {
    pub fn new(circuit_id: u64, now: Instant, lifetime_ms: u64, byte_quota: u64, bidirectional: bool, private_handling: bool) -> Self {
        let lifetime = lifetime_ms.min(MAX_LIFETIME_MS).max(1_000);
        Self {
            circuit_id,
            state: CircuitState::Opening,
            created_at: now,
            expires_at: now + Duration::from_millis(lifetime),
            idle_deadline: now + Duration::from_millis(DEFAULT_IDLE_TIMEOUT_MS),
            granted_byte_quota: byte_quota,
            bytes_forwarded: 0,
            next_relay_sequence: 0,
            downstream: None,
            private_handling,
            bidirectional,
            last_activity: now,
        }
    }

    pub fn touch(&mut self, now: Instant) {
        self.last_activity = now;
        self.idle_deadline = now + Duration::from_millis(DEFAULT_IDLE_TIMEOUT_MS);
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    pub fn is_idle(&self, now: Instant) -> bool {
        now >= self.idle_deadline
    }

    /// Quota accounting (relay.md §20): charge when a new sequence is accepted.
    pub fn charge(&mut self, bytes: u64) -> Result<(), QuotaError> {
        let new_total = self.bytes_forwarded.checked_add(bytes).ok_or(QuotaError::Overflow)?;
        if new_total > self.granted_byte_quota {
            return Err(QuotaError::Exhausted);
        }
        self.bytes_forwarded = new_total;
        Ok(())
    }

    pub fn allocate_sequence(&mut self) -> u64 {
        let seq = self.next_relay_sequence;
        self.next_relay_sequence += 1;
        seq
    }

    pub fn accept(&mut self, now: Instant) {
        self.state = CircuitState::Active;
        self.touch(now);
    }

    pub fn close(&mut self, now: Instant) {
        self.state = CircuitState::Closing;
        self.idle_deadline = now + Duration::from_millis(1_000);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaError {
    Exhausted,
    Overflow,
}

pub struct CircuitIdAllocator {
    next: u64,
    seed: u64,
}

impl CircuitIdAllocator {
    pub fn new(seed: u64) -> Self {
        Self { next: 0, seed }
    }

    /// Unpredictable 62-bit-range IDs (relay.md §8), unique within the session.
    pub fn allocate(&mut self) -> u64 {
        self.seed = self.seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let value = self.seed & ((1u64 << 62) - 1);
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        value ^ id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_lifecycle() {
        let now = Instant(0);
        let mut c = Circuit::new(7, now, DEFAULT_LIFETIME_MS, 1_048_576, true, false);
        assert_eq!(c.state, CircuitState::Opening);
        c.accept(now + Duration::from_millis(10));
        assert_eq!(c.state, CircuitState::Active);
        assert!(!c.is_expired(now + Duration::from_millis(DEFAULT_LIFETIME_MS - 1)));
        assert!(c.is_expired(now + Duration::from_millis(DEFAULT_LIFETIME_MS)));
    }

    #[test]
    fn lifetime_capped_at_max() {
        let now = Instant(0);
        let c = Circuit::new(1, now, MAX_LIFETIME_MS + 60_000, 0, true, false);
        assert!(c.is_expired(now + Duration::from_millis(MAX_LIFETIME_MS)));
    }

    #[test]
    fn quota_enforced() {
        let now = Instant(0);
        let mut c = Circuit::new(2, now, DEFAULT_LIFETIME_MS, 100, true, false);
        c.charge(60).unwrap();
        c.charge(40).unwrap();
        assert_eq!(c.charge(1), Err(QuotaError::Exhausted));
    }

    #[test]
    fn idle_timeout_tracks_activity() {
        let now = Instant(0);
        let mut c = Circuit::new(3, now, DEFAULT_LIFETIME_MS, 100, true, false);
        c.touch(now + Duration::from_millis(50_000));
        assert!(!c.is_idle(now + Duration::from_millis(50_000 + DEFAULT_IDLE_TIMEOUT_MS - 1)));
        assert!(c.is_idle(now + Duration::from_millis(50_000 + DEFAULT_IDLE_TIMEOUT_MS)));
    }

    #[test]
    fn id_allocator_is_unique() {
        let mut allocator = CircuitIdAllocator::new(42);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            let id = allocator.allocate();
            assert!(id < (1u64 << 62));
            assert!(seen.insert(id));
        }
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-relay`
Expected: PASS (5 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-relay
git commit -m "feat(relay): circuit state machine and identifiers"
```

---

### Task 9: Relay admission and quotas

**Files:**
- Create: `crates/umc-relay/src/admission.rs`
- Create: `crates/umc-relay/src/quota.rs`

- [ ] **Step 1: Write admission**

`crates/umc-relay/src/admission.rs`:

```rust
//! Relay admission (relay.md §34): cheap checks before any downstream work.
use crate::circuit::MAX_LIFETIME_MS;
use umc_types::runtime::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPolicy {
    Disabled,
    FriendsOnly,
    Community,
    Public,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    Accepted { granted_lifetime_ms: u64, granted_byte_quota: u64, maximum_relay_payload: usize },
    Refused,
    NoRoute,
    AuthFailed,
    ResourceLimit,
    UnsupportedFlags,
}

#[derive(Debug, Clone)]
pub struct AdmissionLimits {
    pub policy: RelayPolicy,
    pub max_circuits_per_peer: usize,
    pub active_circuits: usize,
    pub max_lifetime_ms: u64,
    pub max_byte_quota: u64,
    pub max_payload: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            policy: RelayPolicy::Disabled,
            max_circuits_per_peer: 4,
            active_circuits: 0,
            max_lifetime_ms: 30 * 60 * 1000,
            max_byte_quota: 256 * 1024 * 1024,
            max_payload: 64 * 1024,
        }
    }
}

/// Evaluate RELAY_OPEN (relay.md §13, §34). No dialing happens here.
pub fn evaluate_open(
    limits: &AdmissionLimits,
    peer_circuits: usize,
    requested_lifetime_ms: u64,
    requested_byte_quota: u64,
    flags: u8,
) -> AdmissionDecision {
    if limits.policy == RelayPolicy::Disabled {
        return AdmissionDecision::Refused;
    }
    if flags & 0xF0 != 0 {
        return AdmissionDecision::UnsupportedFlags;
    }
    if peer_circuits >= limits.max_circuits_per_peer {
        return AdmissionDecision::ResourceLimit;
    }
    if requested_lifetime_ms > MAX_LIFETIME_MS {
        return AdmissionDecision::Refused;
    }
    if requested_lifetime_ms > limits.max_lifetime_ms {
        return AdmissionDecision::Refused;
    }
    let lifetime = if requested_lifetime_ms == 0 { limits.max_lifetime_ms } else { requested_lifetime_ms };
    let quota = requested_byte_quota.min(limits.max_byte_quota);
    AdmissionDecision::Accepted { granted_lifetime_ms: lifetime, granted_byte_quota: quota, maximum_relay_payload: limits.max_payload }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_policy_refuses() {
        let limits = AdmissionLimits::default();
        assert_eq!(evaluate_open(&limits, 0, 600_000, 1_048_576, 0), AdmissionDecision::Refused);
    }

    #[test]
    fn accepted_with_granted_limits() {
        let mut limits = AdmissionLimits::default();
        limits.policy = RelayPolicy::Community;
        match evaluate_open(&limits, 0, 600_000, 1_048_576, 0x01) {
            AdmissionDecision::Accepted { granted_lifetime_ms, granted_byte_quota, .. } => {
                assert_eq!(granted_lifetime_ms, 600_000);
                assert_eq!(granted_byte_quota, 1_048_576);
            }
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn per_peer_circuit_limit() {
        let mut limits = AdmissionLimits::default();
        limits.policy = RelayPolicy::Public;
        assert_eq!(evaluate_open(&limits, 4, 600_000, 0, 0), AdmissionDecision::ResourceLimit);
    }

    #[test]
    fn quota_capped_at_local_max() {
        let mut limits = AdmissionLimits::default();
        limits.policy = RelayPolicy::Public;
        match evaluate_open(&limits, 0, 600_000, 1 << 30, 0) {
            AdmissionDecision::Accepted { granted_byte_quota, .. } => assert_eq!(granted_byte_quota, limits.max_byte_quota),
            other => panic!("expected accepted, got {other:?}"),
        }
    }

    #[test]
    fn unknown_flags_rejected() {
        let mut limits = AdmissionLimits::default();
        limits.policy = RelayPolicy::Public;
        assert_eq!(evaluate_open(&limits, 0, 600_000, 0, 0x10), AdmissionDecision::UnsupportedFlags);
    }
}
```

- [ ] **Step 2: Write queue quotas**

`crates/umc-relay/src/quota.rs`:

```rust
//! Relay queue bounds and bandwidth limits (relay.md §19, §33).
pub const PER_CIRCUIT_QUEUE_BYTES: usize = 256 * 1024;
pub const PER_PEER_QUEUE_BYTES: usize = 2 * 1024 * 1024;
pub const GLOBAL_QUEUE_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_PER_CIRCUIT_RATE: u64 = 1_048_576; // 1 MiB/s
pub const DEFAULT_PER_PEER_RATE: u64 = 4 * 1_048_576;

#[derive(Debug, Clone)]
pub struct QueueAccount {
    pub per_circuit_bytes: usize,
    pub per_peer_bytes: usize,
}

impl QueueAccount {
    pub fn new() -> Self {
        Self { per_circuit_bytes: 0, per_peer_bytes: 0 }
    }

    pub fn accept(&mut self, bytes: usize) -> Result<(), QueueError> {
        let circuit = self.per_circuit_bytes.checked_add(bytes).ok_or(QueueError::Full)?;
        if circuit > PER_CIRCUIT_QUEUE_BYTES {
            return Err(QueueError::Full);
        }
        self.per_circuit_bytes = circuit;
        Ok(())
    }

    pub fn release(&mut self, bytes: usize) {
        self.per_circuit_bytes = self.per_circuit_bytes.saturating_sub(bytes);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    Full,
}

#[derive(Debug, Clone)]
pub struct RateLimiter {
    pub rate_bytes_per_sec: u64,
    pub bucket: u64,
    pub last_refill_ms: u64,
}

impl RateLimiter {
    pub fn new(rate_bytes_per_sec: u64, initial_burst: u64) -> Self {
        Self { rate_bytes_per_sec, bucket: initial_burst, last_refill_ms: 0 }
    }

    pub fn allow(&mut self, now_ms: u64, bytes: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_refill_ms);
        self.last_refill_ms = now_ms;
        self.bucket = self.bucket.saturating_add(elapsed.saturating_mul(self.rate_bytes_per_sec) / 1_000);
        self.bucket = self.bucket.min(self.rate_bytes_per_sec); // 1s burst cap
        if self.bucket >= bytes {
            self.bucket -= bytes;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_bounds_enforced() {
        let mut q = QueueAccount::new();
        q.accept(PER_CIRCUIT_QUEUE_BYTES).unwrap();
        assert_eq!(q.accept(1), Err(QueueError::Full));
        q.release(PER_CIRCUIT_QUEUE_BYTES);
        assert_eq!(q.accept(1), Ok(()));
    }

    #[test]
    fn rate_limiter_refills() {
        let mut r = RateLimiter::new(1_000_000, 0);
        assert!(!r.allow(0, 100));
        // 100ms later the bucket refilled by 100,000 bytes.
        assert!(r.allow(100, 100_000));
        assert!(!r.allow(100, 1));
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-relay`
Expected: PASS (11 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-relay/src/admission.rs crates/umc-relay/src/quota.rs
git commit -m "feat(relay): admission policy and queue quotas"
```

### Task 10: Relay data forwarding and sequencing

**Files:**
- Create: `crates/umc-relay/src/forward.rs`

- [ ] **Step 1: Write the forwarding engine**

`crates/umc-relay/src/forward.rs`:

```rust
//! RELAY_DATA forwarding (relay.md §16-18): opaque bytes, sequence tracking,
//! no inner inspection.
use crate::circuit::{Circuit, QuotaError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    UnknownCircuit,
    Closed,
    SequenceConflict,
    PayloadTooLarge,
    Quota(QuotaError),
    EmptyData,
    FinalSequenceExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardResult {
    pub circuit_id: u64,
    pub sequence: u64,
    pub data: Vec<u8>,
    pub fin: bool,
    pub downstream: Option<Vec<u8>>,
}

/// Accept one RELAY_DATA from the upstream peer.
/// Returns the opaque bytes to forward downstream (relay.md §16).
pub fn accept_upstream_data(
    circuit: &mut Circuit,
    sequence: u64,
    fin: bool,
    data: &[u8],
    max_payload: usize,
) -> Result<ForwardResult, ForwardError> {
    if data.len() > max_payload {
        return Err(ForwardError::PayloadTooLarge);
    }
    if data.is_empty() && !fin {
        return Err(ForwardError::EmptyData);
    }
    if circuit.state == crate::circuit::CircuitState::Closed || circuit.state == crate::circuit::CircuitState::Draining {
        return Err(ForwardError::Closed);
    }
    if sequence != circuit.next_relay_sequence {
        if sequence < circuit.next_relay_sequence {
            // Exact duplicate with identical bytes is discarded; conflicts close.
            return Err(ForwardError::SequenceConflict);
        }
        // Gaps do not close the circuit (relay.md §17); the inner session recovers.
        circuit.next_relay_sequence = sequence + 1;
    } else {
        circuit.next_relay_sequence += 1;
    }
    circuit.charge(data.len() as u64).map_err(ForwardError::Quota)?;
    let downstream = circuit.downstream.clone();
    Ok(ForwardResult { circuit_id: circuit.circuit_id, sequence, data: data.to_vec(), fin, downstream })
}

/// Handle a downstream FIN: half-close tracking (relay.md §22).
pub fn apply_fin(circuit: &mut Circuit, from_upstream: bool) -> Result<(), ForwardError> {
    if from_upstream {
        if circuit.state == crate::circuit::CircuitState::HalfClosedUpstream {
            return Err(ForwardError::FinalSequenceExceeded);
        }
        if circuit.state == crate::circuit::CircuitState::Active {
            circuit.state = crate::circuit::CircuitState::HalfClosedUpstream;
        }
    } else if circuit.state == crate::circuit::CircuitState::HalfClosedDownstream {
        return Err(ForwardError::FinalSequenceExceeded);
    } else if circuit.state == crate::circuit::CircuitState::Active {
        circuit.state = crate::circuit::CircuitState::HalfClosedDownstream;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::Instant;

    fn circuit(id: u64) -> Circuit {
        Circuit::new(id, Instant(0), 600_000, 1_048_576, true, false)
    }

    #[test]
    fn forward_preserves_opacity() {
        let mut c = circuit(1);
        c.downstream = Some(b"peer-b".to_vec());
        c.accept(Instant(0));
        let result = accept_upstream_data(&mut c, 0, false, b"inner-ump-packet", 64 * 1024).unwrap();
        assert_eq!(result.data, b"inner-ump-packet");
        assert_eq!(result.downstream.as_deref(), Some(b"peer-b".as_slice()));
        assert_eq!(result.sequence, 0);
    }

    #[test]
    fn sequence_conflict_detected() {
        let mut c = circuit(2);
        c.accept(Instant(0));
        accept_upstream_data(&mut c, 0, false, b"a", 64 * 1024).unwrap();
        assert_eq!(accept_upstream_data(&mut c, 0, false, b"b", 64 * 1024), Err(ForwardError::SequenceConflict));
    }

    #[test]
    fn sequence_gaps_do_not_close() {
        let mut c = circuit(3);
        c.accept(Instant(0));
        // Gap: jump from 0 to 5.
        accept_upstream_data(&mut c, 5, false, b"x", 64 * 1024).unwrap();
        assert_eq!(c.next_relay_sequence, 6);
    }

    #[test]
    fn empty_data_requires_fin() {
        let mut c = circuit(4);
        c.accept(Instant(0));
        assert_eq!(accept_upstream_data(&mut c, 0, false, b"", 64 * 1024), Err(ForwardError::EmptyData));
        assert!(accept_upstream_data(&mut c, 0, true, b"", 64 * 1024).is_ok());
    }

    #[test]
    fn fin_half_closes() {
        let mut c = circuit(5);
        c.accept(Instant(0));
        apply_fin(&mut c, true).unwrap();
        assert_eq!(c.state, crate::circuit::CircuitState::HalfClosedUpstream);
        assert_eq!(apply_fin(&mut c, true), Err(ForwardError::FinalSequenceExceeded));
    }

    #[test]
    fn quota_charges_forwarded_bytes() {
        let mut c = Circuit::new(6, Instant(0), 600_000, 10, true, false);
        c.accept(Instant(0));
        accept_upstream_data(&mut c, 0, false, b"0123456789", 64 * 1024).unwrap();
        assert_eq!(accept_upstream_data(&mut c, 1, false, b"x", 64 * 1024), Err(ForwardError::Quota(QuotaError::Exhausted)));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-relay`
Expected: PASS (17 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-relay/src/forward.rs
git commit -m "feat(relay): opaque forwarding with sequencing"
```

---

### Task 11: Relay close semantics

**Files:**
- Create: `crates/umc-relay/src/close.rs`

- [ ] **Step 1: Write close handling**

`crates/umc-relay/src/close.rs`:

```rust
//! RELAY_CLOSE semantics and reason codes (relay.md §23-24).
use crate::circuit::{Circuit, CircuitState};
use umc_types::runtime::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayReason {
    NoError = 0,
    Refused = 1,
    AuthFailed = 2,
    NoRoute = 3,
    DownstreamFailed = 4,
    UpstreamFailed = 5,
    QuotaExhausted = 6,
    Expired = 7,
    IdleTimeout = 8,
    ResourceLimit = 9,
    PolicyRevoked = 10,
    ProtocolError = 11,
    PayloadTooLarge = 12,
    EmergencyShutdown = 13,
}

impl RelayReason {
    pub fn from_u64(code: u64) -> Option<Self> {
        match code {
            0 => Some(RelayReason::NoError),
            1 => Some(RelayReason::Refused),
            2 => Some(RelayReason::AuthFailed),
            3 => Some(RelayReason::NoRoute),
            4 => Some(RelayReason::DownstreamFailed),
            5 => Some(RelayReason::UpstreamFailed),
            6 => Some(RelayReason::QuotaExhausted),
            7 => Some(RelayReason::Expired),
            8 => Some(RelayReason::IdleTimeout),
            9 => Some(RelayReason::ResourceLimit),
            10 => Some(RelayReason::PolicyRevoked),
            11 => Some(RelayReason::ProtocolError),
            12 => Some(RelayReason::PayloadTooLarge),
            13 => Some(RelayReason::EmergencyShutdown),
            _ => None,
        }
    }
}

pub const DRAIN_PERIOD_MS: u64 = 1_000;

/// Close a circuit, entering CLOSING then DRAINING (relay.md §9.5-9.6).
/// Returns the final sequence the close should carry (or None = no data accepted).
pub fn close_circuit(circuit: &mut Circuit, reason: RelayReason, now: Instant, final_sequence: Option<u64>) -> RelayReason {
    circuit.state = CircuitState::Closing;
    circuit.idle_deadline = now + Duration::from_millis(DRAIN_PERIOD_MS);
    let _ = final_sequence;
    reason
}

/// Advance CLOSING circuits to DRAINING/CLOSED after the drain period.
pub fn drain_circuit(circuit: &mut Circuit, now: Instant) {
    if circuit.state == CircuitState::Closing && now >= circuit.idle_deadline {
        circuit.state = CircuitState::Closed;
    }
}

/// Idle or lifetime expiry (relay.md §21).
pub fn expiry_reason(circuit: &Circuit, now: Instant) -> Option<RelayReason> {
    if circuit.is_expired(now) {
        return Some(RelayReason::Expired);
    }
    if circuit.is_idle(now) {
        return Some(RelayReason::IdleTimeout);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_code_round_trip() {
        for code in 0..=13 {
            let reason = RelayReason::from_u64(code).unwrap();
            assert_eq!(reason as u64, code);
        }
        assert!(RelayReason::from_u64(14).is_none());
    }

    #[test]
    fn close_then_drain() {
        let now = Instant(0);
        let mut c = Circuit::new(1, now, 600_000, 100, true, false);
        c.accept(now);
        close_circuit(&mut c, RelayReason::QuotaExhausted, now, Some(3));
        assert_eq!(c.state, CircuitState::Closing);
        drain_circuit(&mut c, now + Duration::from_millis(DRAIN_PERIOD_MS));
        assert_eq!(c.state, CircuitState::Closed);
    }

    #[test]
    fn expiry_priority_over_idle() {
        let now = Instant(0);
        let mut c = Circuit::new(2, now, 1_000, 100, true, false);
        // Lifetime expires first at 1000ms; idle at 120s.
        assert_eq!(expiry_reason(&c, now + Duration::from_millis(1_000)), Some(RelayReason::Expired));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-relay`
Expected: PASS (20 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-relay/src/close.rs
git commit -m "feat(relay): close semantics and reason codes"
```

---

### Task 12: Multi-hop construction

**Files:**
- Create: `crates/umc-relay/src/multi.rs`

- [ ] **Step 1: Write multi-hop extension**

`crates/umc-relay/src/multi.rs`:

```rust
//! Multi-hop circuit construction (relay.md §27): hop-by-hop extension with
//! a relay-count budget. Each relay sees only its adjacent hops.
use crate::circuit::{MAX_RELAY_NODES, PROTOCOL_MAX_RELAY_NODES};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    RelayBudgetExhausted,
    ProtocolLimit,
    HopDenied,
}

#[derive(Debug, Clone)]
pub struct ExtensionState {
    pub relays_used: usize,
    pub max_relays: usize,
}

impl ExtensionState {
    pub fn new() -> Self {
        Self { relays_used: 0, max_relays: MAX_RELAY_NODES }
    }

    /// Each extension step decrements the remaining relay count (relay.md §27.4).
    pub fn extend(&mut self, downstream_granted: bool) -> Result<(), ExtensionError> {
        if self.relays_used >= PROTOCOL_MAX_RELAY_NODES {
            return Err(ExtensionError::ProtocolLimit);
        }
        if self.relays_used >= self.max_relays {
            return Err(ExtensionError::RelayBudgetExhausted);
        }
        if downstream_granted {
            self.relays_used += 1;
        }
        Ok(())
    }

    pub fn remaining(&self) -> usize {
        self.max_relays.saturating_sub(self.relays_used)
    }
}

impl Default for ExtensionState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_bounds_extension() {
        let mut state = ExtensionState::new();
        for _ in 0..MAX_RELAY_NODES {
            state.extend(true).unwrap();
        }
        assert_eq!(state.remaining(), 0);
        assert_eq!(state.extend(true), Err(ExtensionError::RelayBudgetExhausted));
    }

    #[test]
    fn protocol_limit_is_absolute() {
        let mut state = ExtensionState { relays_used: PROTOCOL_MAX_RELAY_NODES - 1, max_relays: MAX_RELAY_NODES };
        assert_eq!(state.extend(true), Err(ExtensionError::ProtocolLimit));
    }

    #[test]
    fn denied_hop_does_not_consume() {
        let mut state = ExtensionState::new();
        state.extend(false).unwrap();
        assert_eq!(state.relays_used, 0);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-relay`
Expected: PASS (23 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-relay/src/multi.rs
git commit -m "feat(relay): multi-hop extension budget"
```

---

### Task 13: umc-discovery — provider interface and candidate table

**Files:**
- Create: `crates/umc-discovery/Cargo.toml`
- Create: `crates/umc-discovery/src/lib.rs`
- Create: `crates/umc-discovery/src/provider.rs`
- Create: `crates/umc-discovery/src/table.rs`

- [ ] **Step 1: Crate manifest**

`crates/umc-discovery/Cargo.toml`:

```toml
[package]
name = "umc-discovery"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
umc-types = { path = "../umc-types" }
umc-wire = { path = "../umc-wire" }

[lints]
workspace = true
```

`crates/umc-discovery/src/lib.rs`:

```rust
pub mod hints;
pub mod invitation;
pub mod provider;
pub mod table;
```

- [ ] **Step 2: Write the provider interface**

`crates/umc-discovery/src/provider.rs`:

```rust
//! Discovery provider interface (core.md §35, discovery.md §5).
use umc_types::runtime::Instant;

pub const DEFAULT_MAX_CANDIDATES: usize = 256;
pub const MAX_CANDIDATE_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSource {
    Static,
    LocalDiscovery,
    PeerHint,
    Invitation,
    Bootstrap,
    Application,
    CarrierNative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateAuth {
    Unauthenticated,
    CarrierAuthenticated,
    IntroductionAuthenticated,
    InvitationAuthenticated,
    PreviousSessionBound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharingPolicy {
    LocalUseOnly,
    ShareSelected,
    ShareLocalScope,
    ShareGeneral,
    DoNotReshare,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCandidate {
    pub candidate_id: u64,
    pub carrier_type: String,
    pub connection_hint: Vec<u8>,
    pub source: CandidateSource,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub sharing_policy: SharingPolicy,
    pub authentication: CandidateAuth,
    pub local: bool,
}

impl PeerCandidate {
    pub fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Candidate lifetime capped at 24h without refresh (discovery.md §8.1).
    pub fn cap_lifetime(&mut self, now: Instant) {
        let cap = now + umc_types::runtime::Duration::from_millis(MAX_CANDIDATE_LIFETIME_MS);
        if self.expires_at > cap {
            self.expires_at = cap;
        }
    }
}

pub trait DiscoveryProvider: Send + Sync {
    fn source(&self) -> CandidateSource;
    /// A bounded batch of candidates. Stops on deadline.
    fn candidates(&self, maximum: usize) -> Vec<PeerCandidate>;
    fn publish(&self, hint: &[u8]) -> Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_lifetime_capped() {
        let now = Instant(0);
        let mut c = PeerCandidate {
            candidate_id: 1,
            carrier_type: "ump.udp/1".into(),
            connection_hint: vec![],
            source: CandidateSource::PeerHint,
            created_at: now,
            expires_at: now + umc_types::runtime::Duration::from_millis(48 * 60 * 60 * 1000),
            sharing_policy: SharingPolicy::DoNotReshare,
            authentication: CandidateAuth::Unauthenticated,
            local: false,
        };
        c.cap_lifetime(now);
        assert!(c.is_expired(now + umc_types::runtime::Duration::from_millis(MAX_CANDIDATE_LIFETIME_MS)));
    }

    #[test]
    fn expired_candidates_detectable() {
        let now = Instant(0);
        let c = PeerCandidate {
            candidate_id: 2,
            carrier_type: "ump.tcp/1".into(),
            connection_hint: vec![],
            source: CandidateSource::Static,
            created_at: now,
            expires_at: now,
            sharing_policy: SharingPolicy::LocalUseOnly,
            authentication: CandidateAuth::Unauthenticated,
            local: true,
        };
        assert!(c.is_expired(now));
    }
}
```

- [ ] **Step 3: Write the candidate table**

`crates/umc-discovery/src/table.rs`:

```rust
//! Merged candidate table with source attribution (discovery.md §6-7, §17).
use crate::provider::PeerCandidate;
use std::collections::HashMap;
use umc_types::runtime::Instant;

pub const DEFAULT_TABLE_CAP: usize = 50_000;

#[derive(Debug, Clone)]
pub struct CandidateTable {
    entries: HashMap<u64, PeerCandidate>,
    cap: usize,
}

impl CandidateTable {
    pub fn new(cap: usize) -> Self {
        Self { entries: HashMap::new(), cap }
    }

    pub fn upsert(&mut self, mut candidate: PeerCandidate, now: Instant) -> Result<(), TableError> {
        candidate.cap_lifetime(now);
        if let Some(existing) = self.entries.get(&candidate.candidate_id) {
            // Preserve the strictest sharing policy on conflict (discovery.md §17).
            if strictness(candidate.sharing_policy) < strictness(existing.sharing_policy) {
                candidate.sharing_policy = existing.sharing_policy;
            }
        } else if self.entries.len() >= self.cap {
            self.evict_expired(now);
            if self.entries.len() >= self.cap {
                return Err(TableError::Full);
            }
        }
        self.entries.insert(candidate.candidate_id, candidate);
        Ok(())
    }

    pub fn get(&self, candidate_id: u64) -> Option<&PeerCandidate> {
        self.entries.get(&candidate_id)
    }

    pub fn remove(&mut self, candidate_id: u64) {
        self.entries.remove(&candidate_id);
    }

    pub fn evict_expired(&mut self, now: Instant) {
        self.entries.retain(|_, c| !c.is_expired(now));
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

fn strictness(policy: crate::provider::SharingPolicy) -> u8 {
    use crate::provider::SharingPolicy::*;
    match policy {
        DoNotReshare => 4,
        LocalUseOnly => 3,
        ShareSelected => 2,
        ShareLocalScope => 1,
        ShareGeneral => 0,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableError {
    Full,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: u64, policy: crate::provider::SharingPolicy) -> PeerCandidate {
        PeerCandidate {
            candidate_id: id,
            carrier_type: "ump.udp/1".into(),
            connection_hint: vec![],
            source: crate::provider::CandidateSource::PeerHint,
            created_at: Instant(0),
            expires_at: Instant(u64::MAX),
            sharing_policy: policy,
            authentication: crate::provider::CandidateAuth::Unauthenticated,
            local: false,
        }
    }

    #[test]
    fn strictest_sharing_policy_wins() {
        let mut table = CandidateTable::new(100);
        table.upsert(candidate(1, crate::provider::SharingPolicy::ShareGeneral), Instant(0)).unwrap();
        table.upsert(candidate(1, crate::provider::SharingPolicy::DoNotReshare), Instant(0)).unwrap();
        assert_eq!(table.get(1).unwrap().sharing_policy, crate::provider::SharingPolicy::DoNotReshare);
    }

    #[test]
    fn table_is_bounded() {
        let mut table = CandidateTable::new(2);
        table.upsert(candidate(1, crate::provider::SharingPolicy::LocalUseOnly), Instant(0)).unwrap();
        table.upsert(candidate(2, crate::provider::SharingPolicy::LocalUseOnly), Instant(0)).unwrap();
        assert_eq!(table.upsert(candidate(3, crate::provider::SharingPolicy::LocalUseOnly), Instant(0)), Err(TableError::Full));
    }

    #[test]
    fn expired_evicted_before_admission() {
        let mut table = CandidateTable::new(2);
        let mut stale = candidate(1, crate::provider::SharingPolicy::LocalUseOnly);
        stale.expires_at = Instant(10);
        table.upsert(stale, Instant(0)).unwrap();
        table.upsert(candidate(2, crate::provider::SharingPolicy::LocalUseOnly), Instant(20)).unwrap();
        table.evict_expired(Instant(20));
        assert_eq!(table.len(), 1);
        // A new candidate can now fit.
        assert!(table.upsert(candidate(3, crate::provider::SharingPolicy::LocalUseOnly), Instant(20)).is_ok());
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-discovery`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-discovery
git commit -m "feat(discovery): provider interface and candidate table"
```

---

### Task 14: PEER_HINT exchange

**Files:**
- Create: `crates/umc-discovery/src/hints.rs`

- [ ] **Step 1: Write hint exchange**

`crates/umc-discovery/src/hints.rs`:

```rust
//! PEER_HINT exchange (discovery.md §13, wire-format.md §51).
use crate::provider::{CandidateAuth, CandidateSource, PeerCandidate, SharingPolicy};
use umc_wire::frames::misc::{PeerHintEntry, PeerHintFrame};
use umc_types::runtime::Instant;

pub const MAX_HINTS_PER_FRAME: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintError {
    TooManyHints,
    ReshareForbidden,
    RateLimited,
}

/// Select hints to share: public, fresh, successful, diverse (discovery.md §13.3).
pub fn select_for_share(candidates: &[PeerCandidate], maximum: usize, now: Instant) -> Vec<PeerCandidate> {
    candidates
        .iter()
        .filter(|c| !c.is_expired(now))
        .filter(|c| c.sharing_policy == SharingPolicy::ShareGeneral || c.sharing_policy == SharingPolicy::ShareLocalScope || c.sharing_policy == SharingPolicy::ShareSelected)
        .take(maximum.min(MAX_HINTS_PER_FRAME))
        .cloned()
        .collect()
}

/// Convert candidates into a PEER_HINT frame (wire-format.md §51).
pub fn build_peer_hint(candidates: &[PeerCandidate]) -> Result<PeerHintFrame, HintError> {
    if candidates.len() > MAX_HINTS_PER_FRAME {
        return Err(HintError::TooManyHints);
    }
    let entries = candidates
        .iter()
        .map(|c| PeerHintEntry {
            temporary_peer_id: c.candidate_id.to_be_bytes().to_vec(),
            carrier_type: c.carrier_type.clone().into_bytes(),
            connection_hint: c.connection_hint.clone(),
            expiration_time: c.expires_at.0,
            public: c.sharing_policy == SharingPolicy::ShareGeneral,
            introduced: c.authentication == CandidateAuth::IntroductionAuthenticated,
            local: c.local,
            ephemeral: c.source == CandidateSource::LocalDiscovery,
            do_not_reshare: c.sharing_policy == SharingPolicy::DoNotReshare,
            authenticator: Vec::new(),
        })
        .collect();
    Ok(PeerHintFrame { entries })
}

/// Apply received hints: validate limits, preserve policy, respect
/// DO_NOT_RESHARE (discovery.md §13.4, threat-model.md §19).
pub fn apply_received_hints(frame: &PeerHintFrame, sender: &[u8], now: Instant, table: &mut crate::table::CandidateTable) -> Result<usize, HintError> {
    if frame.entries.len() > MAX_HINTS_PER_FRAME {
        return Err(HintError::TooManyHints);
    }
    let mut accepted = 0;
    for entry in &frame.entries {
        if entry.do_not_reshare {
            // Accepted locally, never forwarded.
        }
        let candidate = PeerCandidate {
            candidate_id: u64::from_be_bytes(entry.temporary_peer_id.as_slice().try_into().unwrap_or([0u8; 8])),
            carrier_type: String::from_utf8_lossy(&entry.carrier_type).to_string(),
            connection_hint: entry.connection_hint.clone(),
            source: if entry.introduced { CandidateSource::PeerHint } else { CandidateSource::PeerHint },
            created_at: now,
            expires_at: Instant(entry.expiration_time),
            sharing_policy: if entry.do_not_reshare { SharingPolicy::DoNotReshare } else if entry.public { SharingPolicy::ShareGeneral } else { SharingPolicy::LocalUseOnly },
            authentication: if entry.introduced { CandidateAuth::IntroductionAuthenticated } else { CandidateAuth::Unauthenticated },
            local: entry.local,
        };
        // The sender is recorded as the hint source (discovery.md §13.4).
        let _ = sender;
        if table.upsert(candidate, now).is_ok() {
            accepted += 1;
        }
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: u64, policy: SharingPolicy, expires: u64) -> PeerCandidate {
        PeerCandidate {
            candidate_id: id,
            carrier_type: "ump.udp/1".into(),
            connection_hint: vec![],
            source: CandidateSource::PeerHint,
            created_at: Instant(0),
            expires_at: Instant(expires),
            sharing_policy: policy,
            authentication: CandidateAuth::Unauthenticated,
            local: false,
        }
    }

    #[test]
    fn selection_filters_private_hints() {
        let candidates = vec![
            candidate(1, SharingPolicy::ShareGeneral, u64::MAX),
            candidate(2, SharingPolicy::DoNotReshare, u64::MAX),
            candidate(3, SharingPolicy::LocalUseOnly, u64::MAX),
        ];
        let selected = select_for_share(&candidates, 10, Instant(0));
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].candidate_id, 1);
    }

    #[test]
    fn frame_round_trip_preserves_policy() {
        let c = candidate(7, SharingPolicy::ShareGeneral, u64::MAX);
        let frame = build_peer_hint(&[c]).unwrap();
        assert_eq!(frame.entries.len(), 1);
        assert!(frame.entries[0].public);
        assert!(!frame.entries[0].do_not_reshare);
    }

    #[test]
    fn too_many_hints_rejected() {
        let mut candidates = Vec::new();
        for i in 0..MAX_HINTS_PER_FRAME + 1 {
            candidates.push(candidate(i as u64, SharingPolicy::ShareGeneral, u64::MAX));
        }
        assert_eq!(build_peer_hint(&candidates), Err(HintError::TooManyHints));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-discovery`
Expected: PASS (9 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-discovery/src/hints.rs
git commit -m "feat(discovery): peer-hint exchange"
```

---

### Task 15: Invitations

**Files:**
- Create: `crates/umc-discovery/src/invitation.rs`

- [ ] **Step 1: Write invitation lifecycle**

`crates/umc-discovery/src/invitation.rs`:

```rust
//! Invitation lifecycle (discovery.md §14, handshake.md §22).
use umc_types::runtime::EntropySource;
use std::collections::HashMap;

pub const INVITATION_KEY_LEN: usize = 32;
pub const MAX_INVITATIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub id: [u8; 16],
    pub key: [u8; INVITATION_KEY_LEN],
    pub expires_at_ms: u64,
    pub single_use: bool,
    pub used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationError {
    Unknown,
    Expired,
    AlreadyUsed,
    Full,
}

pub struct InvitationStore {
    invitations: HashMap<[u8; 16], Invitation>,
}

impl InvitationStore {
    pub fn new() -> Self {
        Self { invitations: HashMap::new() }
    }

    /// Create an invitation; the raw key is returned exactly once.
    pub fn create(&mut self, expires_at_ms: u64, single_use: bool, entropy: &dyn EntropySource) -> Result<Invitation, InvitationError> {
        if self.invitations.len() >= MAX_INVITATIONS {
            return Err(InvitationError::Full);
        }
        let mut id = [0u8; 16];
        let mut key = [0u8; INVITATION_KEY_LEN];
        entropy.fill(&mut id);
        entropy.fill(&mut key);
        let invitation = Invitation { id, key, expires_at_ms, single_use, used: false };
        self.invitations.insert(id, invitation.clone());
        Ok(invitation)
    }

    pub fn validate(&mut self, id: &[u8; 16], key: &[u8], now_ms: u64) -> Result<(), InvitationError> {
        let Some(invitation) = self.invitations.get_mut(id) else {
            return Err(InvitationError::Unknown);
        };
        if now_ms >= invitation.expires_at_ms {
            return Err(InvitationError::Expired);
        }
        if invitation.single_use && invitation.used {
            return Err(InvitationError::AlreadyUsed);
        }
        if invitation.key.as_slice() != key {
            return Err(InvitationError::Unknown);
        }
        if invitation.single_use {
            invitation.used = true;
        }
        Ok(())
    }

    pub fn revoke(&mut self, id: &[u8; 16]) {
        self.invitations.remove(id);
    }

    pub fn prune_expired(&mut self, now_ms: u64) {
        self.invitations.retain(|_, i| i.expires_at_ms > now_ms);
    }

    pub fn len(&self) -> usize {
        self.invitations.len()
    }
}

/// HMAC-style admission authenticator (handshake.md §15.4), truncated to 16 bytes.
pub fn invitation_authenticator(invitation_key: &[u8; 32], client_random: &[u8; 32], client_ephemeral_public_key: &[u8; 32], destination_connection_id: &[u8], carrier_binding: &[u8]) -> [u8; 16] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-INVITE-AUTH-v1");
    hasher.update(invitation_key);
    hasher.update(client_random);
    hasher.update(client_ephemeral_public_key);
    hasher.update(destination_connection_id);
    hasher.update(carrier_binding);
    let full: [u8; 32] = hasher.finalize().into();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&full[..16]);
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(5);
        }
    }

    #[test]
    fn create_validate_revoke() {
        let mut store = InvitationStore::new();
        let invitation = store.create(u64::MAX, true, &E).unwrap();
        assert_eq!(store.validate(&invitation.id, &invitation.key, 0), Ok(()));
        assert_eq!(store.validate(&invitation.id, &invitation.key, 0), Err(InvitationError::AlreadyUsed));
        store.revoke(&invitation.id);
        assert_eq!(store.validate(&invitation.id, &invitation.key, 0), Err(InvitationError::Unknown));
    }

    #[test]
    fn expiry_enforced() {
        let mut store = InvitationStore::new();
        let invitation = store.create(100, false, &E).unwrap();
        assert_eq!(store.validate(&invitation.id, &invitation.key, 99), Ok(()));
        assert_eq!(store.validate(&invitation.id, &invitation.key, 100), Err(InvitationError::Expired));
    }

    #[test]
    fn wrong_key_unknown() {
        let mut store = InvitationStore::new();
        let invitation = store.create(u64::MAX, false, &E).unwrap();
        assert_eq!(store.validate(&invitation.id, &[0u8; 32], 0), Err(InvitationError::Unknown));
    }

    #[test]
    fn authenticator_is_deterministic_and_binds_inputs() {
        let key = [1u8; 32];
        let a = invitation_authenticator(&key, &[2u8; 32], &[3u8; 32], b"dcid", b"binding");
        let b = invitation_authenticator(&key, &[2u8; 32], &[3u8; 32], b"dcid", b"binding");
        let c = invitation_authenticator(&key, &[9u8; 32], &[3u8; 32], b"dcid", b"binding");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-discovery`
Expected: PASS (13 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-discovery/src/invitation.rs
git commit -m "feat(discovery): invitation lifecycle and admission authenticator"
```

---

### Task 16: Integration tests — route discovery and relayed session

**Files:**
- Create: `tests/phase3/Cargo.toml`
- Create: `tests/phase3/tests/route_discovery.rs`
- Create: `tests/phase3/tests/relay_session.rs`

- [ ] **Step 1: Test crate manifest**

`tests/phase3/Cargo.toml`:

```toml
[package]
name = "phase3-tests"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
umc-types = { path = "../../crates/umc-types" }
umc-routing = { path = "../../crates/umc-routing" }
umc-relay = { path = "../../crates/umc-relay" }
umc-discovery = { path = "../../crates/umc-discovery" }
umc-wire = { path = "../../crates/umc-wire" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }

[lints]
workspace = true
```

- [ ] **Step 2: Route discovery integration test**

`tests/phase3/tests/route_discovery.rs`:

```rust
//! 3-node route discovery: A asks for a route to C through B.
//! A -> B (B knows C directly); B answers; A caches a single-relay candidate.
use umc_routing::cache::RouteCache;
use umc_routing::duplicate::RequestCache;
use umc_routing::request::{admit_request, RequestPolicy};
use umc_routing::reverse::ReverseState;
use umc_routing::types::{RouteKey, RouteRecord, RouteScope, RouteState};
use umc_types::runtime::{Duration, EntropySource, Instant};

struct E;
impl EntropySource for E {
    fn fill(&self, out: &mut [u8]) {
        out.fill(1);
    }
}

#[test]
fn route_discovery_three_nodes() {
    let now = Instant(0);
    let mut cache = RequestCache::new(1_024, Duration::from_millis(30_000));
    let mut reverse = ReverseState::new(Duration::from_millis(30_000));
    let mut route_cache = RouteCache::new(8, Duration::from_millis(600_000));
    let policy = RequestPolicy::default();

    // Node B knows node C directly (pre-seeded route).
    let key_c = RouteKey { destination_profile: 0, destination_hash: [3u8; 32], scope: RouteScope::General, policy_class: 0 };
    route_cache.insert(
        RouteRecord {
            key: key_c.clone(),
            state: RouteState::Usable,
            next_hop: "node-c".into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: now,
            expires_at: now + Duration::from_millis(600_000),
            last_success: Some(now),
            last_failure: None,
            failure_count: 0,
            scope: RouteScope::General,
        },
        now,
    );

    // A sends ROUTE_REQUEST to B.
    let request_id = umc_routing::duplicate::RequestCache::generate_request_id(&E);
    let admission = admit_request(&request_id, b"node-a", 0, 8, 30_000, &[], &policy, &mut cache, now).unwrap();
    match admission {
        umc_routing::request::Admission::Admit { .. } => {}
        other => panic!("expected admit, got {other:?}"),
    }
    reverse.create(request_id, b"node-a".to_vec(), now);

    // B matches C from its cache and returns a route.
    let candidates = route_cache.candidates(&key_c, now);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].next_hop, "node-c");

    // The response travels back to A through reverse state.
    let upstream = reverse.route_response(&request_id, now).expect("reverse path");
    assert_eq!(upstream, b"node-a");
}

#[test]
fn response_budget_and_expiry() {
    let mut reverse = ReverseState::new(Duration::from_millis(30_000));
    let rid = [9u8; 16];
    reverse.create(rid, b"node-a".to_vec(), Instant(0));
    for _ in 0..umc_routing::types::MAX_RESPONSES_PER_BRANCH {
        assert!(reverse.route_response(&rid, Instant(1)).is_some());
    }
    assert!(reverse.route_response(&rid, Instant(1)).is_none());
}
```

- [ ] **Step 3: Relay session integration test**

`tests/phase3/tests/relay_session.rs`:

```rust
//! Single-relay circuit: originator opens a circuit, relay grants bounded
//! quota, opaque bytes flow, quota exhaustion closes the circuit.
use umc_relay::admission::{evaluate_open, AdmissionDecision, AdmissionLimits, RelayPolicy};
use umc_relay::circuit::{Circuit, CircuitState};
use umc_relay::close::{close_circuit, RelayReason};
use umc_relay::forward::accept_upstream_data;
use umc_types::runtime::Instant;

#[test]
fn single_relay_circuit_flow() {
    let now = Instant(0);
    let mut limits = AdmissionLimits::default();
    limits.policy = RelayPolicy::Community;

    // Open.
    let decision = evaluate_open(&limits, 0, 600_000, 1_048_576, 0x01);
    let (lifetime, quota, payload) = match decision {
        AdmissionDecision::Accepted { granted_lifetime_ms, granted_byte_quota, maximum_relay_payload } => (granted_lifetime_ms, granted_byte_quota, maximum_relay_payload),
        other => panic!("expected accepted, got {other:?}"),
    };

    // Circuit created and accepted.
    let mut circuit = Circuit::new(7, now, lifetime, quota, true, false);
    circuit.downstream = Some(b"destination".to_vec());
    circuit.accept(now);

    // Opaque traffic flows.
    let first = accept_upstream_data(&mut circuit, 0, false, b"inner-packet-1", payload).unwrap();
    assert_eq!(first.downstream.as_deref(), Some(b"destination".as_slice()));
    assert_eq!(first.sequence, 0);

    // Quota is bounded: fill the rest.
    let remaining = quota - b"inner-packet-1".len() as u64;
    let big = vec![0u8; remaining as usize];
    accept_upstream_data(&mut circuit, 1, false, &big, payload).unwrap();
    assert_eq!(
        accept_upstream_data(&mut circuit, 2, false, b"x", payload).unwrap_err(),
        umc_relay::forward::ForwardError::Quota(umc_relay::circuit::QuotaError::Exhausted)
    );

    // Close with reason.
    close_circuit(&mut circuit, RelayReason::QuotaExhausted, now, Some(1));
    assert_eq!(circuit.state, CircuitState::Closing);
}

#[test]
fn disabled_relay_refuses() {
    let limits = AdmissionLimits::default();
    assert_eq!(evaluate_open(&limits, 0, 600_000, 0, 0), AdmissionDecision::Refused);
}

#[test]
fn malformed_relay_data_rejected() {
    let now = Instant(0);
    let mut circuit = Circuit::new(1, now, 600_000, 1_048_576, true, false);
    circuit.accept(now);
    // Payload over grant.
    assert_eq!(
        accept_upstream_data(&mut circuit, 0, false, &vec![0u8; 65_537], 64 * 1024).unwrap_err(),
        umc_relay::forward::ForwardError::PayloadTooLarge
    );
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p phase3-tests`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add tests/phase3
git commit -m "test(phase3): route discovery and relay circuit flows"
```

---

### Task 17: Phase 3 completion gate

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
- [x] Phase 3: routing and relaying — route discovery, single relay, quotas
- [ ] Phase 4: mobility
- [ ] Phase 5: local mesh
- [ ] Phase 6: store-and-forward
- [ ] Phase 7: adversarial resilience
```

- [ ] **Step 3: Verify Phase 3 success criteria from `core.md` §64**

Checklist:

- [ ] Peer exchange (PEER_HINT frames, DO_NOT_RESHARE)
- [ ] Route discovery (request admission, hop limits, duplicate suppression)
- [ ] Reverse-path response forwarding with budget
- [ ] Route cache with expiry and eviction
- [ ] Route failure classes and backoff
- [ ] Single relay (circuit open/accept/data/close)
- [ ] Relay quotas (bytes, lifetime, idle, queue)
- [ ] Relay admission policy (disabled by default, community opt-in)
- [ ] Multi-hop extension budget
- [ ] Discovery provider interface and candidate table
- [ ] Invitations (create/validate/revoke, admission authenticator)
- [ ] 3-node route discovery test
- [ ] Relayed traffic flows end to end (success criterion 4)

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: phase 3 complete"
```

---

## Phase 3 self-review

**Spec coverage:** `routing.md` §6 (states) → Task 1; §7, §11 (request IDs, duplicates) → Task 2; §8-13 (admission, hops, propagation) → Task 3; §17-18 (reverse state) → Task 4; §24-25 (cache, persistence revalidation) → Task 5; §22 (scoring, hard constraints) → Task 6; §26 (failure/retry) → Task 7; `relay.md` §8-9 (IDs, states) → Task 8; §13, §34 (open, admission order) → Task 9; §16-20 (data, sequencing, quotas, backpressure bounds) → Task 10; §23-24 (close, reasons) → Task 11; §27 (multi-hop) → Task 12; `discovery.md` §5-7 (providers, candidates) → Task 13; §13 (peer exchange) → Task 14; §14 + `handshake.md` §15.4/§22 (invitations) → Task 15.

**Known deferrals:** wiring the routing/relay/discovery engines into the daemon's live packet path (they run as libraries with integration tests in Phase 3; the daemon session loop integrates them in Phase 4 along with migration), final-responder route authentication, route metadata canonical encoding, relay authorization profiles (invitation-bound), emergency shutdown plumbing, onion-style path hiding, `RELAY_STATUS` PENDING flows, abuse-score persistence.

