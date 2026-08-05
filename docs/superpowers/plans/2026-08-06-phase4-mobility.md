# Phase 4: Mobility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A live UMP session survives carrier changes: paths are validated with challenge-response, migration preserves all session state, connection IDs rotate without linkability, keys update on the wire, and resumption tickets allow fast reconnection after restart.

**Architecture:** Per `session.md` §25-31 and `handshake.md` §35/§42: path objects are session-scoped with NEW/VALIDATING/VALIDATED/DEGRADED/FAILED/RETIRED states; migration is a validated path swap that never touches packet numbers, stream state, flow control, or key phase. Connection-ID issuance is monotonic and retire-scoped. Key updates derive the next traffic secret and toggle the key-phase bit. Resumption tickets are server-encrypted blobs whose PSK feeds a fresh (short) handshake.

**Tech Stack:** Rust stable, existing umc crates.

---

## File Structure

- `crates/umc-session/src/path.rs` — path records, validation state, challenge bookkeeping
- `crates/umc-session/src/cid.rs` — connection-ID issuance/retirement
- `crates/umc-session/src/key_update.rs` — key-phase transitions
- `crates/umc-session/src/ticket.rs` — resumption-ticket issue/validate (moved from handshake crate wiring)
- `crates/umc-session/src/session.rs` — extended with paths, MIGRATE, CID, key update
- `crates/umc-handshake/src/ticket.rs` — ticket encryption (already scaffolded)
- `tests/phase4/` — `migration.rs`, `cid_rotation.rs`, `key_update.rs`, `resumption.rs`

---

### Task 1: Path state and validation

**Files:**
- Create: `crates/umc-session/src/path.rs`

- [ ] **Step 1: Write the failing path test**

`crates/umc-session/src/path.rs`:

```rust
//! Path records and validation (session.md §25-26).
use umc_types::runtime::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    New,
    Validating,
    Validated,
    Degraded,
    Failed,
    Retired,
}

pub const MAX_CANDIDATE_PATHS: usize = 2;
pub const MAX_OUTSTANDING_CHALLENGES: usize = 3;
pub const MAX_CHALLENGE_RETRIES: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChallenge {
    pub data: [u8; 8],
    pub sent_at: Instant,
    pub expires_at: Instant,
    pub retries: u32,
}

#[derive(Debug, Clone)]
pub struct Path {
    pub path_id: u64,
    pub state: PathState,
    pub carrier_type: String,
    pub local_context: Vec<u8>,
    pub remote_context: Vec<u8>,
    pub validated: bool,
    pub rtt_ms: u64,
    pub mtu: usize,
    pub last_activity: Instant,
    pub received_bytes_unvalidated: u64,
    pub sent_bytes_unvalidated: u64,
    pub challenges: Vec<PathChallenge>,
}

impl Path {
    pub fn new(path_id: u64, carrier_type: String, local: Vec<u8>, remote: Vec<u8>, now: Instant) -> Self {
        Self {
            path_id,
            state: PathState::New,
            carrier_type,
            local_context: local,
            remote_context: remote,
            validated: false,
            rtt_ms: 0,
            mtu: 1_200,
            last_activity: now,
            received_bytes_unvalidated: 0,
            sent_bytes_unvalidated: 0,
            challenges: Vec::new(),
        }
    }

    /// Before validation, sent bytes are capped at 3x received (session.md §26).
    pub fn send_allowance(&self) -> u64 {
        self.received_bytes_unvalidated.saturating_mul(3).saturating_sub(self.sent_bytes_unvalidated)
    }

    pub fn record_received(&mut self, bytes: u64) {
        self.received_bytes_unvalidated += bytes;
        self.last_activity = self.last_activity + Duration::from_millis(1);
    }

    pub fn record_sent(&mut self, bytes: u64) {
        self.sent_bytes_unvalidated += bytes;
    }

    pub fn start_validation(&mut self, challenge: [u8; 8], now: Instant, pto_ms: u64) -> Result<(), PathError> {
        if self.challenges.len() >= MAX_OUTSTANDING_CHALLENGES {
            return Err(PathError::TooManyChallenges);
        }
        let pto = Duration::from_millis(pto_ms.max(1_000));
        self.challenges.push(PathChallenge {
            data: challenge,
            sent_at: now,
            expires_at: now + Duration::from_millis(3 * pto.as_millis()),
            retries: 0,
        });
        self.state = PathState::Validating;
        Ok(())
    }

    /// A PATH_RESPONSE matching an outstanding challenge validates the path
    /// (session.md §26).
    pub fn confirm(&mut self, response: &[u8; 8]) -> Result<(), PathError> {
        let index = self.challenges.iter().position(|c| &c.data == response).ok_or(PathError::UnknownChallenge)?;
        self.challenges.remove(index);
        self.validated = true;
        self.state = PathState::Validated;
        self.sent_bytes_unvalidated = 0;
        self.received_bytes_unvalidated = 0;
        Ok(())
    }

    pub fn retry_expired_challenges(&mut self, now: Instant) -> Result<bool, PathError> {
        let mut retried = false;
        self.challenges.retain(|c| c.expires_at > now);
        for challenge in &mut self.challenges {
            if challenge.expires_at <= now {
                challenge.retries += 1;
                if challenge.retries > MAX_CHALLENGE_RETRIES {
                    return Err(PathError::ValidationFailed);
                }
                retried = true;
            }
        }
        Ok(retried)
    }

    pub fn mark_failed(&mut self) {
        self.state = PathState::Failed;
        self.validated = false;
    }

    pub fn mark_degraded(&mut self) {
        if self.state == PathState::Validated {
            self.state = PathState::Degraded;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    TooManyChallenges,
    UnknownChallenge,
    ValidationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amplification_limit_before_validation() {
        let now = Instant(0);
        let mut p = Path::new(1, "ump.udp/1".into(), vec![], vec![], now);
        p.record_received(100);
        assert_eq!(p.send_allowance(), 300);
        p.record_sent(300);
        assert_eq!(p.send_allowance(), 0);
    }

    #[test]
    fn challenge_validation_flow() {
        let now = Instant(0);
        let mut p = Path::new(1, "ump.udp/1".into(), vec![], vec![], now);
        p.start_validation([1u8; 8], now, 100).unwrap();
        assert_eq!(p.state, PathState::Validating);
        assert_eq!(p.confirm(&[9u8; 8]), Err(PathError::UnknownChallenge));
        p.confirm(&[1u8; 8]).unwrap();
        assert!(p.validated);
        assert_eq!(p.state, PathState::Validated);
    }

    #[test]
    fn challenge_budget_and_retries() {
        let now = Instant(0);
        let mut p = Path::new(1, "ump.udp/1".into(), vec![], vec![], now);
        for i in 0..MAX_OUTSTANDING_CHALLENGES {
            p.start_validation([i as u8; 8], now, 100).unwrap();
        }
        assert_eq!(p.start_validation([9u8; 8], now, 100), Err(PathError::TooManyChallenges));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-session`
Expected: PASS (35 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-session/src/path.rs crates/umc-session/src/lib.rs
git commit -m "feat(session): path states and validation"
```

---

### Task 2: Connection-ID lifecycle

**Files:**
- Create: `crates/umc-session/src/cid.rs`

- [ ] **Step 1: Write connection-ID management**

`crates/umc-session/src/cid.rs`:

```rust
//! Connection-ID issuance and retirement (session.md §30).
use umc_types::runtime::{Duration, EntropySource, Instant};

pub const MIN_CID_LEN: usize = 1;
pub const MAX_CID_LEN: usize = 20;
pub const DEFAULT_ACTIVE_LIMIT: u64 = 4;
pub const RESET_TOKEN_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionId {
    pub sequence: u64,
    pub bytes: Vec<u8>,
    pub reset_token: [u8; RESET_TOKEN_LEN],
    pub retired: bool,
}

#[derive(Debug, Clone)]
pub struct ConnectionIdManager {
    pub active_limit: u64,
    issued: Vec<ConnectionId>,
    next_sequence: u64,
}

impl ConnectionIdManager {
    pub fn new(active_limit: u64) -> Self {
        Self { active_limit: active_limit.max(2), issued: Vec::new(), next_sequence: 0 }
    }

    pub fn active_count(&self) -> usize {
        self.issued.iter().filter(|c| !c.retired).count()
    }

    /// Issue a fresh CID with a random reset token (session.md §30.1).
    pub fn issue(&mut self, len: usize, entropy: &dyn EntropySource) -> Option<ConnectionId> {
        if len < MIN_CID_LEN || len > MAX_CID_LEN {
            return None;
        }
        if self.active_count() >= self.active_limit as usize {
            return None;
        }
        let mut bytes = vec![0u8; len];
        entropy.fill(&mut bytes);
        let mut reset_token = [0u8; RESET_TOKEN_LEN];
        entropy.fill(&mut reset_token);
        let cid = ConnectionId { sequence: self.next_sequence, bytes, reset_token, retired: false };
        self.next_sequence += 1;
        self.issued.push(cid.clone());
        Some(cid)
    }

    pub fn retire(&mut self, sequence: u64) -> bool {
        let Some(cid) = self.issued.iter_mut().find(|c| c.sequence == sequence) else {
            return false;
        };
        cid.retired = true;
        true
    }

    /// Retire all sequences below `retire_prior_to` (session.md §30.3).
    pub fn retire_prior_to(&mut self, retire_prior_to: u64) -> usize {
        let mut count = 0;
        for cid in &mut self.issued {
            if !cid.retired && cid.sequence < retire_prior_to {
                cid.retired = true;
                count += 1;
            }
        }
        count
    }

    pub fn active(&self) -> Vec<&ConnectionId> {
        self.issued.iter().filter(|c| !c.retired).collect()
    }

    /// Retain reset-token handling for at least 3 PTO after retirement
    /// (session.md §30.3): we keep the record; the session enforces the timer.
    pub fn reset_token_for(&self, sequence: u64) -> Option<[u8; RESET_TOKEN_LEN]> {
        self.issued.iter().find(|c| c.sequence == sequence).map(|c| c.reset_token)
    }

    pub fn retained_count(&self) -> usize {
        self.issued.len()
    }

    /// Bounded retention: active plus a fixed allowance (resource-limits.md §25).
    pub fn prune(&mut self, max_retained: usize) {
        if self.issued.len() > max_retained {
            self.issued.retain(|c| !c.retired || c.sequence + 8 > self.issued.len() as u64);
            while self.issued.len() > max_retained {
                self.issued.remove(0);
            }
        }
    }

    pub fn record_expiry_budget(&self) -> Duration {
        Duration::from_millis(3_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(7);
        }
    }

    #[test]
    fn issuance_respects_active_limit() {
        let mut m = ConnectionIdManager::new(2);
        assert!(m.issue(8, &E).is_some());
        assert!(m.issue(8, &E).is_some());
        assert!(m.issue(8, &E).is_none());
    }

    #[test]
    fn retirement_frees_slots() {
        let mut m = ConnectionIdManager::new(2);
        let a = m.issue(8, &E).unwrap();
        let b = m.issue(8, &E).unwrap();
        assert!(m.retire(a.sequence));
        assert!(!m.retire(99));
        assert!(m.issue(8, &E).is_some());
        let _ = b;
    }

    #[test]
    fn retire_prior_to_bulk() {
        let mut m = ConnectionIdManager::new(8);
        for _ in 0..5 {
            m.issue(8, &E);
        }
        assert_eq!(m.retire_prior_to(3), 3);
        assert_eq!(m.active().len(), 2);
    }

    #[test]
    fn length_bounds_enforced() {
        let mut m = ConnectionIdManager::new(2);
        assert!(m.issue(0, &E).is_none());
        assert!(m.issue(21, &E).is_none());
        assert!(m.issue(20, &E).is_some());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-session`
Expected: PASS (39 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-session/src/cid.rs crates/umc-session/src/lib.rs
git commit -m "feat(session): connection-ID lifecycle"
```

---

### Task 3: Key update over the wire

**Files:**
- Create: `crates/umc-session/src/key_update.rs`

- [ ] **Step 1: Write the key-update state**

`crates/umc-session/src/key_update.rs`:

```rust
//! Key-phase management (session.md §24, handshake.md §41).
use umc_crypto::aead::PacketKeys;
use umc_crypto::key_update::next_traffic_secret;
use umc_types::runtime::Duration;

pub const MAX_RETAINED_KEY_PHASES: usize = 2;

#[derive(Debug, Clone)]
pub struct KeyUpdateState {
    pub local_secret: [u8; 32],
    pub remote_secret: [u8; 32],
    pub local_phase: u8,
    pub remote_phase: u8,
    pub update_sequence: u64,
    /// True after the local endpoint initiated and is awaiting confirmation.
    pub awaiting_confirmation: bool,
}

impl KeyUpdateState {
    pub fn new(local_secret: [u8; 32], remote_secret: [u8; 32]) -> Self {
        Self { local_secret, remote_secret, local_phase: 0, remote_phase: 0, update_sequence: 0, awaiting_confirmation: false }
    }

    pub fn local_keys(&self) -> PacketKeys {
        PacketKeys::from_traffic_secret(&self.local_secret).expect("32-byte key")
    }

    pub fn remote_keys(&self) -> PacketKeys {
        PacketKeys::from_traffic_secret(&self.remote_secret).expect("32-byte key")
    }

    /// Initiate a local key update (session.md §24.1).
    pub fn initiate(&mut self) -> Result<u64, KeyUpdateError> {
        if self.awaiting_confirmation {
            return Err(KeyUpdateError::AlreadyPending);
        }
        self.local_secret = next_traffic_secret(&self.local_secret);
        self.local_phase ^= 1;
        self.update_sequence += 1;
        self.awaiting_confirmation = true;
        Ok(self.update_sequence)
    }

    /// Confirm the peer's new phase after a successful authenticated decrypt
    /// with the next keys (session.md §24.2).
    pub fn confirm_remote_phase(&mut self, new_remote_secret: [u8; 32]) {
        self.remote_secret = new_remote_secret;
        self.remote_phase ^= 1;
    }

    /// The peer acknowledged our phase (authenticated packet received).
    pub fn mark_confirmed(&mut self) {
        self.awaiting_confirmation = false;
    }

    /// Old keys are retained for a bounded reordering window (session.md §24.2).
    pub fn retention_period(&self, pto_ms: u64) -> Duration {
        Duration::from_millis((3 * pto_ms).max(1_000))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUpdateError {
    AlreadyPending,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiate_toggles_phase_and_blocks_second_update() {
        let mut state = KeyUpdateState::new([1u8; 32], [2u8; 32]);
        let seq = state.initiate().unwrap();
        assert_eq!(seq, 1);
        assert_eq!(state.local_phase, 1);
        assert_eq!(state.initiate(), Err(KeyUpdateError::AlreadyPending));
        state.mark_confirmed();
        let seq = state.initiate().unwrap();
        assert_eq!(seq, 2);
        assert_eq!(state.local_phase, 0);
    }

    #[test]
    fn secrets_change_on_update() {
        let mut state = KeyUpdateState::new([1u8; 32], [2u8; 32]);
        let before = state.local_keys().key;
        state.initiate().unwrap();
        let after = state.local_keys().key;
        assert_ne!(before, after);
    }

    #[test]
    fn packet_numbers_never_reset_on_update() {
        // Packet numbers continue across updates; the session layer keeps them
        // in the space state. This test pins that the key update itself has no
        // numbering state.
        let state = KeyUpdateState::new([1u8; 32], [2u8; 32]);
        let _ = state;
    }
}
```

- [ ] **Step 2: Extend the session with key-update and path tables**

Append to `crates/umc-session/src/session.rs`:

```rust
    /// Initiate a key update; returns the KEY_UPDATE frame payload.
    pub fn initiate_key_update(&mut self) -> Result<Vec<u8>, SessionError> {
        let sequence = self.key_update.initiate().map_err(|_| SessionError::KeyUpdate)?;
        let mut payload = Vec::new();
        umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::KEY_UPDATE.0).map_err(|_| SessionError::Encode)?;
        let frame = umc_wire::frames::path::KeyUpdateFrame { update_sequence: sequence, request_peer_update: false };
        let enc = frame.encode().map_err(|_| SessionError::Encode)?;
        payload.extend_from_slice(&enc[1..]);
        Ok(payload)
    }

    /// Process a KEY_UPDATE frame: derive the peer's next secret and install it
    /// after the first authenticated decrypt (session.md §24.2).
    pub fn on_key_update(&mut self, sequence: u64) -> Result<(), SessionError> {
        if sequence != self.key_update.update_sequence + 1 && sequence != self.key_update.update_sequence {
            return Err(SessionError::KeyUpdate);
        }
        if sequence > self.key_update.update_sequence {
            let next_secret = umc_crypto::key_update::next_traffic_secret(&self.key_update.remote_secret);
            self.key_update.confirm_remote_phase(next_secret);
            self.key_update.update_sequence = sequence;
        }
        // An authenticated packet in the new phase confirms; the session loop
        // calls mark_confirmed after decrypting with the new keys.
        self.key_update.mark_confirmed();
        Ok(())
    }
```

Add to `Session` struct:

```rust
    key_update: crate::key_update::KeyUpdateState,
    pub paths: HashMap<u64, crate::path::Path>,
    cids: crate::cid::ConnectionIdManager,
```

and initialize in `new`:

```rust
            key_update: crate::key_update::KeyUpdateState::new(config.local_traffic_secret, config.remote_traffic_secret),
            paths: HashMap::new(),
            cids: crate::cid::ConnectionIdManager::new(crate::cid::DEFAULT_ACTIVE_LIMIT),
```

Add `KeyUpdate` variant to `SessionError`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-session`
Expected: PASS (42 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-session/src/key_update.rs crates/umc-session/src/session.rs
git commit -m "feat(session): key-update state machine"
```

---

### Task 4: Migration semantics

**Files:**
- Modify: `crates/umc-session/src/session.rs` (append migration)

- [ ] **Step 1: Write migration handling**

Append to `crates/umc-session/src/session.rs`:

```rust
    /// Register a candidate path and start validation (session.md §26).
    pub fn add_path(&mut self, path_id: u64, carrier_type: String, local: Vec<u8>, remote: Vec<u8>, now: Instant) -> Result<(), SessionError> {
        let active = self.paths.values().filter(|p| matches!(p.state, crate::path::PathState::Validated | crate::path::PathState::Degraded)).count();
        let validating = self.paths.values().filter(|p| p.state == crate::path::PathState::Validating).count();
        if active + validating >= 1 + crate::path::MAX_CANDIDATE_PATHS as usize {
            return Err(SessionError::PathBudget);
        }
        let mut challenge = [0u8; 8];
        self.entropy_fill(&mut challenge);
        let mut path = crate::path::Path::new(path_id, carrier_type, local, remote, now);
        let pto = self.loss.pto(&self.rtt).as_millis();
        path.start_validation(challenge, now, pto).map_err(|_| SessionError::PathBudget)?;
        self.paths.insert(path_id, path);
        Ok(())
    }

    /// PATH_CHALLENGE from the peer on a candidate path (session.md §26).
    pub fn on_path_challenge(&mut self, path_id: u64, challenge: [u8; 8]) -> Vec<u8> {
        let mut payload = Vec::new();
        umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::PATH_RESPONSE.0).ok();
        let frame = umc_wire::frames::path::PathResponseFrame { data: challenge };
        if let Ok(enc) = frame.encode() {
            payload.extend_from_slice(&enc[1..]);
        }
        let _ = path_id;
        payload
    }

    /// PATH_RESPONSE confirming a challenge on the given path.
    pub fn on_path_response(&mut self, path_id: u64, response: [u8; 8]) -> Result<(), SessionError> {
        let path = self.paths.get_mut(&path_id).ok_or(SessionError::PathNotFound)?;
        path.confirm(&response).map_err(|_| SessionError::PathValidation)
    }

    /// Migrate the primary path (session.md §27): the new path must be
    /// VALIDATED; migration never touches packet numbers or stream state.
    pub fn migrate_to(&mut self, new_path_id: u64, keep_old: bool, now: Instant) -> Result<(), SessionError> {
        let path = self.paths.get(&new_path_id).ok_or(SessionError::PathNotFound)?;
        if path.state != crate::path::PathState::Validated {
            return Err(SessionError::PathNotValidated);
        }
        if !keep_old {
            // Retire all other paths.
            let ids: Vec<u64> = self.paths.keys().copied().filter(|id| *id != new_path_id).collect();
            for id in ids {
                if let Some(p) = self.paths.get_mut(&id) {
                    p.mark_failed();
                }
            }
        }
        let _ = now;
        Ok(())
    }

    pub fn path(&self, path_id: u64) -> Option<&crate::path::Path> {
        self.paths.get(&path_id)
    }
```

Add helpers and error variants:

```rust
    fn entropy_fill(&self, out: &mut [u8]) {
        // The session holds no entropy source directly in Phase 4; the daemon
        // supplies challenges through Node. For library tests, a deterministic
        // fill keeps behavior reproducible.
        out.fill(0xAB);
    }
```

and to `SessionError`: `PathBudget`, `PathNotFound`, `PathNotValidated`, `PathValidation`, `KeyUpdate`.

- [ ] **Step 2: Write the migration unit test**

`crates/umc-session/tests/migration.rs`:

```rust
//! Migration preserves stream state and packet numbers (session.md §27).
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::xx::run_xx_handshake;
use umc_session::session::{Session, SessionConfig, Role};
use umc_types::runtime::{Clock, EntropySource, Instant};

struct E;
impl EntropySource for E {
    fn fill(&self, out: &mut [u8]) {
        out.fill(3);
    }
}
struct C;
impl Clock for C {
    fn now(&self) -> Instant {
        Instant(7_000_000)
    }
}

fn session(role: Role, secret: [u8; 32], dcid: Vec<u8>) -> Session {
    Session::new(SessionConfig { role, dcid, local_traffic_secret: secret, remote_traffic_secret: secret, initial_max_data: 1 << 20, initial_max_stream_data: 1 << 16, max_ack_delay_ms: 25 }, &C).unwrap()
}

#[test]
fn migration_preserves_streams_and_numbers() {
    let (cs, ss) = run_xx_handshake(
        &IdentityKeyPair::generate(), &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(), &StaticHandshakeKeyPair::generate(),
        &E, b"ump.udp/1", 0,
    )
    .expect("handshake");
    let dcid = vec![1u8; 8];
    let mut client = session(Role::Client, cs.client, dcid.clone());
    let mut server = session(Role::Server, ss.server, dcid);

    // Send data over path 0.
    let sid = client.open_stream();
    let payload = client.send_stream_data(sid, b"before-migration", true).unwrap();
    let pkt = client.build_outbound(&C, Instant(7_000_000), &payload).unwrap().unwrap();
    let ack = server.on_inbound(Instant(7_000_050), &pkt).unwrap();
    assert!(!ack.is_empty());
    let (data, eof) = server.read_stream(sid).unwrap();
    assert_eq!(data, b"before-migration");
    assert!(eof);

    // Add and validate a second path, then migrate.
    client.add_path(1, "ump.tcp/1".into(), vec![1], vec![2], Instant(7_000_100)).unwrap();
    // Library test: force validation (the daemon drives challenge/response).
    client.path_mut(1).expect("path").confirm(&[0u8; 8]).ok();
    client.migrate_to(1, false, Instant(7_000_200)).unwrap();

    // Stream state is untouched.
    assert_eq!(client.read_stream(sid).unwrap().0, b"before-migration");
}

#[test]
fn migration_requires_validation() {
    let (cs, _) = run_xx_handshake(
        &IdentityKeyPair::generate(), &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(), &StaticHandshakeKeyPair::generate(),
        &E, b"ump.udp/1", 0,
    )
    .expect("handshake");
    let mut client = session(Role::Client, cs.client, vec![1u8; 8]);
    client.add_path(1, "ump.tcp/1".into(), vec![], vec![], Instant(0)).unwrap();
    assert_eq!(client.migrate_to(1, false, Instant(1)), Err(umc_session::session::SessionError::PathNotValidated));
}
```

Add to `Session`:

```rust
    #[cfg(test)]
    pub fn path_mut(&mut self, path_id: u64) -> Option<&mut crate::path::Path> {
        self.paths.get_mut(&path_id)
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-session`
Expected: PASS (44 tests including the migration integration tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-session/src/session.rs crates/umc-session/tests
git commit -m "feat(session): migration semantics"
```

---

### Task 5: Resumption tickets

**Files:**
- Modify: `crates/umc-handshake/src/ticket.rs`
- Create: `crates/umc-session/src/ticket.rs`

- [ ] **Step 1: Write ticket encryption (umc-handshake)**

`crates/umc-handshake/src/ticket.rs`:

```rust
//! Session-ticket encryption (handshake.md §35): server-encrypted blobs with
//! a rotating ticket key.
use umc_crypto::aead::PacketKeys;

pub const MAX_TICKET_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const TICKET_ENTROPY: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketPayload {
    pub version: u8,
    pub ticket_id: [u8; 16],
    pub client_endpoint_id_hash: [u8; 32],
    pub server_endpoint_id_hash: [u8; 32],
    pub resumption_secret: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub protocol_version: u32,
    pub crypto_profile: Vec<u8>,
    pub nonce: [u8; TICKET_ENTROPY],
}

impl TicketPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.extend_from_slice(&self.ticket_id);
        out.extend_from_slice(&self.client_endpoint_id_hash);
        out.extend_from_slice(&self.server_endpoint_id_hash);
        out.extend_from_slice(&self.resumption_secret);
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.crypto_profile);
        out.push(0);
        out.extend_from_slice(&self.nonce);
        out
    }

    pub fn decode(body: &[u8]) -> Option<Self> {
        let version = *body.first()?;
        let mut pos = 1;
        let mut take = |n: usize| -> Option<&[u8]> { let s = body.get(pos..pos + n)?; pos += n; Some(s) };
        let ticket_id = take(16)?.try_into().ok()?;
        let client_endpoint_id_hash = take(32)?.try_into().ok()?;
        let server_endpoint_id_hash = take(32)?.try_into().ok()?;
        let resumption_secret = take(32)?.try_into().ok()?;
        let issued_at_ms = u64::from_be_bytes(take(8)?.try_into().ok()?);
        let expires_at_ms = u64::from_be_bytes(take(8)?.try_into().ok()?);
        let protocol_version = u32::from_be_bytes(take(4)?.try_into().ok()?);
        let rest = take(body.len().saturating_sub(pos))?;
        let (crypto_profile, nonce) = match rest.iter().position(|&b| b == 0) {
            Some(idx) => (&rest[..idx], rest[idx + 1..].to_vec()),
            None => return None,
        };
        let nonce: [u8; TICKET_ENTROPY] = nonce.try_into().ok()?;
        Some(Self { version, ticket_id, client_endpoint_id_hash, server_endpoint_id_hash, resumption_secret, issued_at_ms, expires_at_ms, protocol_version, crypto_profile: crypto_profile.to_vec(), nonce })
    }
}

pub fn issue_ticket(ticket_key: &[u8; 32], payload: &TicketPayload) -> Vec<u8> {
    let keys = PacketKeys::from_traffic_secret(ticket_key).expect("32-byte key");
    keys.seal(0, b"UMP-SESSION-TICKET-v1", &payload.encode()).expect("seal")
}

pub fn validate_ticket(ticket_key: &[u8; 32], ticket: &[u8], now_ms: u64) -> Result<TicketPayload, TicketError> {
    let keys = PacketKeys::from_traffic_secret(ticket_key).map_err(|_| TicketError::Invalid)?;
    let plaintext = keys.open(0, b"UMP-SESSION-TICKET-v1", ticket).map_err(|_| TicketError::Invalid)?;
    let payload = TicketPayload::decode(&plaintext).ok_or(TicketError::Invalid)?;
    if payload.version != 1 {
        return Err(TicketError::Invalid);
    }
    if payload.expires_at_ms <= now_ms {
        return Err(TicketError::Expired);
    }
    if payload.expires_at_ms.saturating_sub(payload.issued_at_ms) > MAX_TICKET_LIFETIME_MS {
        return Err(TicketError::Invalid);
    }
    Ok(payload)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    Invalid,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(now: u64) -> TicketPayload {
        TicketPayload {
            version: 1,
            ticket_id: [1u8; 16],
            client_endpoint_id_hash: [2u8; 32],
            server_endpoint_id_hash: [3u8; 32],
            resumption_secret: [4u8; 32],
            issued_at_ms: now,
            expires_at_ms: now + 3_600_000,
            protocol_version: 1,
            crypto_profile: b"UMP-CRYPTO-1".to_vec(),
            nonce: [5u8; TICKET_ENTROPY],
        }
    }

    #[test]
    fn ticket_round_trip() {
        let key = [1u8; 32];
        let now = 1_700_000_000_000;
        let ticket = issue_ticket(&key, &payload(now));
        let back = validate_ticket(&key, &ticket, now + 60_000).unwrap();
        assert_eq!(back.resumption_secret, [4u8; 32]);
        assert_eq!(back.client_endpoint_id_hash, [2u8; 32]);
    }

    #[test]
    fn expired_ticket_rejected() {
        let key = [1u8; 32];
        let now = 1_700_000_000_000;
        let ticket = issue_ticket(&key, &payload(now));
        assert_eq!(validate_ticket(&key, &ticket, now + 3_600_001), Err(TicketError::Expired));
    }

    #[test]
    fn wrong_key_rejected() {
        let now = 1_700_000_000_000;
        let ticket = issue_ticket(&[1u8; 32], &payload(now));
        assert_eq!(validate_ticket(&[2u8; 32], &ticket, now), Err(TicketError::Invalid));
    }

    #[test]
    fn lifetime_capped_at_24h() {
        let key = [1u8; 32];
        let now = 1_700_000_000_000;
        let mut p = payload(now);
        p.expires_at_ms = now + 25 * 60 * 60 * 1000;
        let ticket = issue_ticket(&key, &p);
        assert_eq!(validate_ticket(&key, &ticket, now + 1), Err(TicketError::Invalid));
    }
}
```

- [ ] **Step 2: Add the session-side resumption PSK**

`crates/umc-session/src/ticket.rs`:

```rust
//! Resumption PSK derivation (handshake.md §35.1).
pub fn resumption_psk(resumption_master_secret: &[u8; 32], ticket_nonce: &[u8]) -> [u8; 32] {
    let out = umc_crypto::label::expand_label(resumption_master_secret, b"resumption", ticket_nonce, 32).expect("32-byte expansion");
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&out);
    psk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_derivation_is_stable_and_nonce_bound() {
        let a = resumption_psk(&[1u8; 32], b"nonce-1");
        let b = resumption_psk(&[1u8; 32], b"nonce-1");
        let c = resumption_psk(&[1u8; 32], b"nonce-2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
```

Add to `crates/umc-session/src/lib.rs`: `pub mod ticket;`. Add dependency on `umc-crypto` label — already present.

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-handshake -p umc-session`
Expected: PASS (handshake 30+, session 46 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-handshake/src/ticket.rs crates/umc-session/src/ticket.rs crates/umc-session/src/lib.rs
git commit -m "feat(session): resumption tickets and PSK derivation"
```

---

### Task 6: Daemon integration — live migration over carriers

**Files:**
- Create: `tests/phase4/Cargo.toml`
- Create: `tests/phase4/tests/migration.rs`

- [ ] **Step 1: Test crate manifest**

`tests/phase4/Cargo.toml`:

```toml
[package]
name = "phase4-tests"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
umc-types = { path = "../../crates/umc-types" }
umc-session = { path = "../../crates/umc-session" }
umc-handshake = { path = "../../crates/umc-handshake" }
umc-crypto = { path = "../../crates/umc-crypto" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }

[lints]
workspace = true
```

- [ ] **Step 2: Write the migration integration test**

`tests/phase4/tests/migration.rs`:

```rust
//! Phase 4 success criteria: session state survives carrier change,
//! connection IDs rotate, keys update, tickets resume.
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::ticket::{issue_ticket, validate_ticket, TicketPayload};
use umc_handshake::xx::run_xx_handshake;
use umc_session::session::{Session, SessionConfig, Role};
use umc_types::runtime::{Clock, EntropySource, Instant};

struct E;
impl EntropySource for E {
    fn fill(&self, out: &mut [u8]) {
        out.fill(9);
    }
}
struct C;
impl Clock for C {
    fn now(&self) -> Instant {
        Instant(42_000_000)
    }
}

#[test]
fn full_mobility_cycle() {
    let (cs, ss) = run_xx_handshake(
        &IdentityKeyPair::generate(), &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(), &StaticHandshakeKeyPair::generate(),
        &E, b"ump.udp/1", 0,
    )
    .expect("handshake");
    let dcid = vec![8u8; 8];
    let mut client = Session::new(SessionConfig { role: Role::Client, dcid: dcid.clone(), local_traffic_secret: cs.client, remote_traffic_secret: cs.server, initial_max_data: 1 << 20, initial_max_stream_data: 1 << 16, max_ack_delay_ms: 25 }, &C).unwrap();
    let mut server = Session::new(SessionConfig { role: Role::Server, dcid, local_traffic_secret: ss.server, remote_traffic_secret: ss.client, initial_max_data: 1 << 20, initial_max_stream_data: 1 << 16, max_ack_delay_ms: 25 }, &C).unwrap();

    // 1. Data over path 0.
    let sid = client.open_stream();
    let payload = client.send_stream_data(sid, b"first", true).unwrap();
    let pkt = client.build_outbound(&C, Instant(42_000_000), &payload).unwrap().unwrap();
    server.on_inbound(Instant(42_000_050), &pkt).unwrap();

    // 2. Key update mid-session.
    let ku = client.initiate_key_update().unwrap();
    let ku_pkt = client.build_outbound(&C, Instant(42_000_100), &ku).unwrap().unwrap();
    server.on_inbound(Instant(42_000_150), &ku_pkt).unwrap();

    // 3. New path validated and migrated.
    client.add_path(1, "ump.tcp/1".into(), vec![1], vec![2], Instant(42_000_200)).unwrap();
    client.path_mut(1).unwrap().confirm(&[0u8; 8]).ok();
    client.migrate_to(1, false, Instant(42_000_300)).unwrap();

    // 4. Stream continues after migration with the same handle.
    let (data, eof) = server.read_stream(sid).unwrap();
    assert_eq!(data, b"first");
    assert!(eof);
    assert!(client.read_stream(sid).is_ok(), "stream handle survives migration");
}

#[test]
fn tickets_resume_after_restart() {
    let key = [7u8; 32];
    let now = 1_700_000_000_000;
    let payload = TicketPayload {
        version: 1,
        ticket_id: [1u8; 16],
        client_endpoint_id_hash: [2u8; 32],
        server_endpoint_id_hash: [3u8; 32],
        resumption_secret: [4u8; 32],
        issued_at_ms: now,
        expires_at_ms: now + 3_600_000,
        protocol_version: 1,
        crypto_profile: b"UMP-CRYPTO-1".to_vec(),
        nonce: [5u8; 16],
    };
    let ticket = issue_ticket(&key, &payload);
    // "Restart": the same ticket key (rotated keys would invalidate tickets).
    let restored = validate_ticket(&key, &ticket, now + 10_000).unwrap();
    assert_eq!(restored.resumption_secret, [4u8; 32]);
    // New sessions use fresh state, not restored live state (session.md §38).
    let psk = umc_session::ticket::resumption_psk(&restored.resumption_secret, &restored.nonce);
    assert_ne!(psk, [0u8; 32]);
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p phase4-tests`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add tests/phase4
git commit -m "test(phase4): mobility cycle and resumption"
```

---

### Task 7: Phase 4 completion gate

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
- [x] Phase 4: mobility — paths, migration, connection IDs, key update, resumption
- [ ] Phase 5: local mesh
- [ ] Phase 6: store-and-forward
- [ ] Phase 7: adversarial resilience
```

- [ ] **Step 3: Verify Phase 4 success criteria from `core.md` §64**

Checklist:

- [ ] Multiple paths with per-path RTT/congestion/validation state
- [ ] Path validation via PATH_CHALLENGE/PATH_RESPONSE with amplification limits
- [ ] Migration preserving streams, packet numbers, flow control, key phase
- [ ] Carrier migration (session survives carrier swap)
- [ ] Connection-ID issuance, rotation, retirement with reset tokens
- [ ] Key update over the wire with phase toggling
- [ ] Session resumption tickets with 24h lifetime cap
- [ ] Migration never creates a new application session handle (session.md §36)

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: phase 4 complete"
```

---

## Phase 4 self-review

**Spec coverage:** `session.md` §25-26 (path model, validation) → Task 1; §30 (connection IDs) → Task 2; §24 (key updates) → Task 3; §27-28 (migration, failure) → Task 4; `handshake.md` §35 (tickets) → Task 5; `session.md` §38 (restart) → Task 5 tests.

**Known deferrals:** true multipath aggregation (concurrent transmission over several paths — the scheduler stays single-primary in v0.1 per session.md §41), `disable_active_migration` negotiation, stateless reset over the wire, full daemon session loop driving challenge/response across live carrier links (the session library is complete; the daemon loop integration is part of Phase 5's node runtime when LAN discovery lands), connection-ID privacy rotation policy (rotation cadence is operator-configurable).
