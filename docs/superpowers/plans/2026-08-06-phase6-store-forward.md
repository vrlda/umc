# Phase 6: Store-and-Forward Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A bundle created while a destination is unreachable is stored, survives disconnection, and is delivered when connectivity returns — with quotas, expiration, deduplication, and explicit custody semantics, all experimental per `decisions.md` §9.

**Architecture:** Per `bundles.md`: payloads are content-addressed objects (storage crate), metadata lives in SQLite, the envelope encrypts to the destination's static handshake key so storage nodes never see plaintext. The bundle manager enforces quotas before allocation, deduplicates by Bundle ID, expires on monotonic clocks, and forwards only on authenticated contacts. One-hop delayed delivery is the v0.1 test target.

**Tech Stack:** Rust stable, existing umc crates.

---

## File Structure

- `crates/umc-bundle/` — `Cargo.toml`, `src/lib.rs`, `envelope.rs` (encryption), `id.rs` (Bundle ID), `manager.rs` (admission/storage/dedup), `expiry.rs`, `forward.rs`, `ack.rs`, `replicate.rs`
- `tests/phase6/` — `delayed_delivery.rs`, `quotas.rs`, `dedup.rs`

---

### Task 1: Bundle envelope encryption

**Files:**
- Create: `crates/umc-bundle/Cargo.toml`
- Create: `crates/umc-bundle/src/lib.rs`
- Create: `crates/umc-bundle/src/envelope.rs`

- [ ] **Step 1: Crate manifest**

`crates/umc-bundle/Cargo.toml`:

```toml
[package]
name = "umc-bundle"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
umc-types = { path = "../umc-types" }
umc-crypto = { path = "../umc-crypto" }
umc-storage = { path = "../umc-storage" }
umc-wire = { path = "../umc-wire" }

[dev-dependencies]
proptest = "1"

[lints]
workspace = true
```

`crates/umc-bundle/src/lib.rs`:

```rust
pub mod ack;
pub mod envelope;
pub mod expiry;
pub mod forward;
pub mod id;
pub mod manager;
pub mod replicate;
```

- [ ] **Step 2: Write the envelope**

`crates/umc-bundle/src/envelope.rs`:

```rust
//! Bundle envelope (bundles.md §7): sealed encryption to the destination's
//! static handshake key with a fresh sender ephemeral. Provisional until
//! v0.2 cryptographic review.
use umc_crypto::aead::PacketKeys;
use umc_crypto::signatures::{StaticHandshakeKeyPair, StaticHandshakePublicKey};

pub const EPHEMERAL_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEnvelope {
    pub sender_ephemeral_public_key: [u8; EPHEMERAL_KEY_LEN],
    pub encrypted_payload: Vec<u8>,
}

/// Seal a bundle payload to the destination (bundles.md §7.2).
pub fn seal_bundle(
    sender_ephemeral: &StaticHandshakeKeyPair,
    destination_static_public_key: &StaticHandshakePublicKey,
    payload: &[u8],
) -> BundleEnvelope {
    let shared = sender_ephemeral.diffie_hellman(destination_static_public_key);
    let key = derive_payload_key(&shared);
    let keys = PacketKeys::from_traffic_secret(&key).expect("32-byte key");
    let ciphertext = keys.seal(0, b"UMP-BUNDLE-v1", payload).expect("seal");
    BundleEnvelope { sender_ephemeral_public_key: sender_ephemeral.public().0, encrypted_payload: ciphertext }
}

/// Open a bundle payload with the destination's static handshake key
/// (bundles.md §7.3: confidentiality + integrity for the stored payload).
pub fn open_bundle(
    destination_static: &StaticHandshakeKeyPair,
    envelope: &BundleEnvelope,
) -> Result<Vec<u8>, BundleEnvelopeError> {
    let peer = StaticHandshakePublicKey(envelope.sender_ephemeral_public_key);
    let shared = destination_static.diffie_hellman(&peer);
    let key = derive_payload_key(&shared);
    let keys = PacketKeys::from_traffic_secret(&key).map_err(|_| BundleEnvelopeError::DecryptFailed)?;
    keys.open(0, b"UMP-BUNDLE-v1", &envelope.encrypted_payload).map_err(|_| BundleEnvelopeError::DecryptFailed)
}

fn derive_payload_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let out = umc_crypto::label::expand_label(shared_secret, b"bundle payload", b"", 32).expect("32-byte expansion");
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleEnvelopeError {
    DecryptFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let sender = StaticHandshakeKeyPair::generate();
        let destination = StaticHandshakeKeyPair::generate();
        let envelope = seal_bundle(&sender, &destination.public(), b"secret bundle");
        let opened = open_bundle(&destination, &envelope).unwrap();
        assert_eq!(opened, b"secret bundle");
    }

    #[test]
    fn wrong_destination_cannot_open() {
        let sender = StaticHandshakeKeyPair::generate();
        let destination = StaticHandshakeKeyPair::generate();
        let attacker = StaticHandshakeKeyPair::generate();
        let envelope = seal_bundle(&sender, &destination.public(), b"secret");
        assert_eq!(open_bundle(&attacker, &envelope), Err(BundleEnvelopeError::DecryptFailed));
    }

    #[test]
    fn tampering_detected() {
        let sender = StaticHandshakeKeyPair::generate();
        let destination = StaticHandshakeKeyPair::generate();
        let mut envelope = seal_bundle(&sender, &destination.public(), b"secret");
        envelope.encrypted_payload[0] ^= 0xFF;
        assert_eq!(open_bundle(&destination, &envelope), Err(BundleEnvelopeError::DecryptFailed));
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-bundle`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-bundle
git commit -m "feat(bundle): sealed envelope encryption"
```

---

### Task 2: Bundle ID derivation

**Files:**
- Create: `crates/umc-bundle/src/id.rs`

- [ ] **Step 1: Write Bundle ID**

`crates/umc-bundle/src/id.rs`:

```rust
//! Bundle ID (bundles.md §6): provisional construction; deduplicates without
//! exposing contents.
use crate::envelope::BundleEnvelope;
use blake2::{Blake2s256, Digest};

pub const BUNDLE_ID_LEN: usize = 32;

/// BundleID = BLAKE2s-256("UMP-BUNDLE-ID-v1" || encrypted_payload_hash ||
/// destination_hint_hash) (bundles.md §6.2). Final derivation is an open
/// design decision before v0.2.
pub fn bundle_id(envelope: &BundleEnvelope, destination_hint: &[u8]) -> [u8; BUNDLE_ID_LEN] {
    let payload_hash: [u8; 32] = {
        let mut hasher = Blake2s256::new();
        hasher.update(&envelope.encrypted_payload);
        hasher.finalize().into()
    };
    let hint_hash: [u8; 32] = {
        let mut hasher = Blake2s256::new();
        hasher.update(destination_hint);
        hasher.finalize().into()
    };
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMP-BUNDLE-ID-v1");
    hasher.update(payload_hash);
    hasher.update(hint_hash);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_crypto::signatures::StaticHandshakeKeyPair;

    fn envelope() -> BundleEnvelope {
        let sender = StaticHandshakeKeyPair::generate();
        let destination = StaticHandshakeKeyPair::generate();
        crate::envelope::seal_bundle(&sender, &destination.public(), b"payload")
    }

    #[test]
    fn id_is_stable_and_content_bound() {
        let e = envelope();
        let a = bundle_id(&e, b"dest-1");
        let b = bundle_id(&e, b"dest-1");
        let c = bundle_id(&e, b"dest-2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn id_does_not_expose_plaintext() {
        let sender = StaticHandshakeKeyPair::generate();
        let destination = StaticHandshakeKeyPair::generate();
        let e1 = crate::envelope::seal_bundle(&sender, &destination.public(), b"plaintext-A");
        let e2 = crate::envelope::seal_bundle(&sender, &destination.public(), b"plaintext-B");
        // Same sender/dest hint: IDs differ because the payloads differ.
        assert_ne!(bundle_id(&e1, b"d"), bundle_id(&e2, b"d"));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-bundle`
Expected: PASS (5 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-bundle/src/id.rs
git commit -m "feat(bundle): bundle identifiers"
```

---

### Task 3: Bundle manager — admission, storage, deduplication

**Files:**
- Create: `crates/umc-bundle/src/manager.rs`

- [ ] **Step 1: Write the manager**

`crates/umc-bundle/src/manager.rs`:

```rust
//! Bundle manager (bundles.md §9-10, §12): validate policy before allocation,
//! store payloads as content-addressed objects, deduplicate by Bundle ID.
use crate::id::{bundle_id, BUNDLE_ID_LEN};
use std::collections::HashMap;
use umc_storage::objects::{blake2s, ObjectStore};
use umc_storage::quota::QuotaAccount;
use umc_storage::store::StoreError;
use umc_types::runtime::{Duration, Instant};

pub const DEFAULT_MAX_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const DEFAULT_MAX_REPLICATION: u64 = 8;
pub const MAX_BUNDLES_PER_SENDER: u64 = 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleStatus {
    Received,
    CustodyAccepted,
    Forwarded,
    Delivered,
    Rejected,
    Expired,
    Evicted,
}

#[derive(Debug, Clone)]
pub struct BundleRecord {
    pub id: [u8; BUNDLE_ID_LEN],
    pub object_id: [u8; 32],
    pub sender: Vec<u8>,
    pub destination_hint: Vec<u8>,
    pub size: usize,
    pub priority: u64,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub replication_count: u64,
    pub custody: bool,
    pub status: BundleStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    QuotaExceeded,
    TooLarge,
    Expired,
    Duplicate,
    Conflict,
    ReplicationLimit,
    NotFound,
    Storage(StoreError),
}

pub struct BundleManager {
    objects: ObjectStore,
    quota: QuotaAccount,
    records: HashMap<[u8; BUNDLE_ID_LEN], BundleRecord>,
    bundles_per_sender: HashMap<Vec<u8>, u64>,
}

impl BundleManager {
    pub fn new(objects: ObjectStore, quota: QuotaAccount) -> Self {
        Self { objects, quota, records: HashMap::new(), bundles_per_sender: HashMap::new() }
    }

    /// Admission (bundles.md §8.1): policy before allocation.
    pub fn admit(
        &mut self,
        payload: &[u8],
        sender: &[u8],
        destination_hint: &[u8],
        priority: u64,
        lifetime_ms: u64,
        replication_limit: u64,
        custody: bool,
        now: Instant,
    ) -> Result<[u8; BUNDLE_ID_LEN], BundleError> {
        if payload.len() > DEFAULT_MAX_BUNDLE_BYTES {
            return Err(BundleError::TooLarge);
        }
        if lifetime_ms > MAX_LIFETIME_MS {
            return Err(BundleError::Expired);
        }
        if replication_limit > DEFAULT_MAX_REPLICATION {
            return Err(BundleError::ReplicationLimit);
        }
        if *self.bundles_per_sender.get(sender).unwrap_or(&0) >= MAX_BUNDLES_PER_SENDER {
            return Err(BundleError::QuotaExceeded);
        }
        // Reserve quota BEFORE allocation (resource-limits.md §32).
        self.quota.reserve(payload.len() as u64).map_err(|_| BundleError::QuotaExceeded)?;
        let object_id = blake2s(payload);
        self.objects.put(&object_id, payload).map_err(BundleError::Storage)?;
        let envelope = crate::envelope::BundleEnvelope { sender_ephemeral_public_key: [0u8; 32], encrypted_payload: payload.to_vec() };
        let id = bundle_id(&envelope, destination_hint);
        if self.records.contains_key(&id) {
            // Duplicate: roll back the reservation, do not store twice (bundles.md §12).
            self.quota.release(payload.len() as u64);
            return Err(BundleError::Duplicate);
        }
        let lifetime = lifetime_ms.max(1_000);
        self.records.insert(
            id,
            BundleRecord {
                id,
                object_id,
                sender: sender.to_vec(),
                destination_hint: destination_hint.to_vec(),
                size: payload.len(),
                priority,
                created_at: now,
                expires_at: now + Duration::from_millis(lifetime),
                replication_count: 0,
                custody,
                status: if custody { BundleStatus::CustodyAccepted } else { BundleStatus::Received },
            },
        );
        *self.bundles_per_sender.entry(sender.to_vec()).or_insert(0) += 1;
        Ok(id)
    }

    pub fn get_payload(&self, id: &[u8; BUNDLE_ID_LEN]) -> Result<Vec<u8>, BundleError> {
        let record = self.records.get(id).ok_or(BundleError::NotFound)?;
        self.objects.get(&record.object_id).map_err(BundleError::Storage)
    }

    pub fn record(&self, id: &[u8; BUNDLE_ID_LEN]) -> Option<&BundleRecord> {
        self.records.get(id)
    }

    pub fn set_status(&mut self, id: &[u8; BUNDLE_ID_LEN], status: BundleStatus) -> Result<(), BundleError> {
        let record = self.records.get_mut(id).ok_or(BundleError::NotFound)?;
        record.status = status;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> BundleManager {
        let dir = std::env::temp_dir().join(format!("umc-bundle-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let objects = ObjectStore::open(dir).unwrap();
        let quota = QuotaAccount::new(umc_storage::quota::Profile::Standard, 0, 1_048_576);
        BundleManager::new(objects, quota)
    }

    #[test]
    fn admit_store_read_round_trip() {
        let mut m = manager();
        let id = m.admit(b"payload", b"sender-a", b"dest-hint", 1, DEFAULT_LIFETIME_MS, 3, false, Instant(0)).unwrap();
        assert_eq!(m.get_payload(&id).unwrap(), b"payload");
        assert_eq!(m.record(&id).unwrap().status, BundleStatus::Received);
    }

    #[test]
    fn duplicates_rejected() {
        let mut m = manager();
        m.admit(b"same", b"s", b"d", 1, DEFAULT_LIFETIME_MS, 3, false, Instant(0)).unwrap();
        assert_eq!(m.admit(b"same", b"s", b"d", 1, DEFAULT_LIFETIME_MS, 3, false, Instant(0)), Err(BundleError::Duplicate));
    }

    #[test]
    fn size_and_lifetime_bounds() {
        let mut m = manager();
        assert_eq!(m.admit(&vec![0u8; DEFAULT_MAX_BUNDLE_BYTES + 1], b"s", b"d", 1, DEFAULT_LIFETIME_MS, 3, false, Instant(0)), Err(BundleError::TooLarge));
        assert_eq!(m.admit(b"x", b"s", b"d", 1, MAX_LIFETIME_MS + 1, 3, false, Instant(0)), Err(BundleError::Expired));
        assert_eq!(m.admit(b"x", b"s", b"d", 1, DEFAULT_LIFETIME_MS, 9, false, Instant(0)), Err(BundleError::ReplicationLimit));
    }

    #[test]
    fn quota_enforced_before_allocation() {
        let dir = std::env::temp_dir().join(format!("umc-bundle-quota-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let objects = ObjectStore::open(dir).unwrap();
        let quota = QuotaAccount::new(umc_storage::quota::Profile::Standard, 0, 10);
        let mut m = BundleManager::new(objects, quota);
        assert_eq!(m.admit(&vec![0u8; 11], b"s", b"d", 1, DEFAULT_LIFETIME_MS, 3, false, Instant(0)), Err(BundleError::QuotaExceeded));
    }

    #[test]
    fn custody_sets_status() {
        let mut m = manager();
        let id = m.admit(b"p", b"s", b"d", 1, DEFAULT_LIFETIME_MS, 3, true, Instant(0)).unwrap();
        assert_eq!(m.record(&id).unwrap().status, BundleStatus::CustodyAccepted);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-bundle`
Expected: PASS (10 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-bundle/src/manager.rs
git commit -m "feat(bundle): manager with admission and dedup"
```

---

### Task 4: Expiration and forwarding

**Files:**
- Create: `crates/umc-bundle/src/expiry.rs`
- Create: `crates/umc-bundle/src/forward.rs`

- [ ] **Step 1: Write expiration**

`crates/umc-bundle/src/expiry.rs`:

```rust
//! Expiration and eviction (bundles.md §11, §19).
use crate::manager::{BundleManager, BundleStatus};
use umc_types::runtime::Instant;

/// Eviction order (resource-limits.md §33): expired, invalid, delivered,
/// unauthenticated, lowest priority, highest replication, largest, oldest.
pub fn evict_expired(manager: &mut BundleManager, now: Instant) -> usize {
    let expired: Vec<[u8; 32]> = manager
        .records_iter()
        .filter(|r| r.expires_at <= now)
        .map(|r| r.id)
        .collect();
    let count = expired.len();
    for id in expired {
        let _ = manager.set_status(&id, BundleStatus::Expired);
        manager.remove(&id);
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{BundleManager, DEFAULT_LIFETIME_MS};
    use umc_storage::objects::ObjectStore;
    use umc_storage::quota::{Profile, QuotaAccount};
    use umc_types::runtime::Duration;

    fn manager() -> BundleManager {
        let dir = std::env::temp_dir().join(format!("umc-expiry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        BundleManager::new(ObjectStore::open(dir).unwrap(), QuotaAccount::new(Profile::Standard, 0, 1_048_576))
    }

    #[test]
    fn expired_bundles_evicted() {
        let mut m = manager();
        m.admit(b"a", b"s", b"d", 1, 1_000, 3, false, Instant(0)).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(evict_expired(&mut m, Instant(1_000)), 1);
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn live_bundles_survive() {
        let mut m = manager();
        m.admit(b"a", b"s", b"d", 1, DEFAULT_LIFETIME_MS, 3, false, Instant(0)).unwrap();
        assert_eq!(evict_expired(&mut m, Instant(1_000)), 0);
        assert_eq!(m.len(), 1);
        let _ = Duration::from_millis(1);
    }
}
```

Add the helpers to `BundleManager`:

```rust
    pub fn records_iter(&self) -> impl Iterator<Item = &BundleRecord> {
        self.records.values()
    }

    pub fn remove(&mut self, id: &[u8; BUNDLE_ID_LEN]) {
        if let Some(record) = self.records.remove(id) {
            self.quota.release(record.size as u64);
            if let Some(count) = self.bundles_per_sender.get_mut(&record.sender) {
                *count = count.saturating_sub(1);
            }
        }
    }
```

- [ ] **Step 2: Write forwarding**

`crates/umc-bundle/src/forward.rs`:

```rust
//! Forwarding on contact (bundles.md §16-17): a handoff proves only that the
//! next node accepted the bundle. No live-route semantics.
use crate::manager::{BundleManager, BundleStatus};
use umc_types::runtime::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    NoContact,
    Expired,
    ReplicationLimit,
    DoNotReplicate,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub destination_hint: Vec<u8>,
    pub peer: Vec<u8>,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct ForwardResult {
    pub id: [u8; 32],
    pub payload: Vec<u8>,
    pub peer: Vec<u8>,
}

/// Select a bundle for handoff on a contact (bundles.md §17.2).
pub fn select_for_contact<'a>(
    manager: &'a BundleManager,
    contact: &Contact,
    now: Instant,
) -> Result<Vec<&'a crate::manager::BundleRecord>, ForwardError> {
    let records: Vec<_> = manager
        .records_iter()
        .filter(|r| r.destination_hint == contact.destination_hint)
        .filter(|r| r.expires_at > now)
        .filter(|r| r.status != BundleStatus::Forwarded && r.status != BundleStatus::Delivered)
        .filter(|r| r.replication_count < crate::manager::DEFAULT_MAX_REPLICATION)
        .collect();
    Ok(records)
}

/// Perform the handoff: bump replication count, mark Forwarded (bundles.md §16).
pub fn handoff(manager: &mut BundleManager, id: &[u8; 32], peer: &[u8]) -> Result<ForwardResult, ForwardError> {
    let record = manager.record_mut(id).ok_or(ForwardError::NotFound)?;
    record.replication_count += 1;
    if record.replication_count > crate::manager::DEFAULT_MAX_REPLICATION {
        return Err(ForwardError::ReplicationLimit);
    }
    record.status = BundleStatus::Forwarded;
    let payload = manager.get_payload(id).map_err(|_| ForwardError::NotFound)?;
    Ok(ForwardResult { id: *id, payload, peer: peer.to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{BundleManager, DEFAULT_LIFETIME_MS};
    use umc_storage::objects::ObjectStore;
    use umc_storage::quota::{Profile, QuotaAccount};
    use umc_types::runtime::Duration;

    fn manager() -> BundleManager {
        let dir = std::env::temp_dir().join(format!("umc-forward-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        BundleManager::new(ObjectStore::open(dir).unwrap(), QuotaAccount::new(Profile::Standard, 0, 1_048_576))
    }

    #[test]
    fn forward_on_matching_contact() {
        let mut m = manager();
        let id = m.admit(b"payload", b"s", b"dest-hint", 1, DEFAULT_LIFETIME_MS, 3, false, Instant(0)).unwrap();
        let contact = Contact { destination_hint: b"dest-hint".to_vec(), peer: b"peer-b".to_vec(), expires_at: Instant(u64::MAX) };
        let selected = select_for_contact(&m, &contact, Instant(1)).unwrap();
        assert_eq!(selected.len(), 1);
        let result = handoff(&mut m, &id, b"peer-b").unwrap();
        assert_eq!(result.payload, b"payload");
        assert_eq!(result.peer, b"peer-b");
        assert_eq!(m.record(&id).unwrap().status, BundleStatus::Forwarded);
        assert_eq!(m.record(&id).unwrap().replication_count, 1);
    }

    #[test]
    fn no_contact_no_match() {
        let mut m = manager();
        m.admit(b"payload", b"s", b"dest-hint", 1, DEFAULT_LIFETIME_MS, 3, false, Instant(0)).unwrap();
        let contact = Contact { destination_hint: b"other-hint".to_vec(), peer: b"p".to_vec(), expires_at: Instant(u64::MAX) };
        assert!(select_for_contact(&m, &contact, Instant(1)).unwrap().is_empty());
    }

    #[test]
    fn replication_limit_stops_forwarding() {
        let mut m = manager();
        let id = m.admit(b"p", b"s", b"d", 1, DEFAULT_LIFETIME_MS, 0, false, Instant(0)).unwrap();
        assert_eq!(handoff(&mut m, &id, b"peer").unwrap_err(), ForwardError::ReplicationLimit);
    }
}
```

Add to `BundleManager`:

```rust
    pub fn record_mut(&mut self, id: &[u8; BUNDLE_ID_LEN]) -> Option<&mut BundleRecord> {
        self.records.get_mut(id)
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-bundle`
Expected: PASS (15 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-bundle/src/expiry.rs crates/umc-bundle/src/forward.rs crates/umc-bundle/src/manager.rs
git commit -m "feat(bundle): expiration and contact forwarding"
```

---

### Task 5: Acknowledgements and replication policy

**Files:**
- Create: `crates/umc-bundle/src/ack.rs`
- Create: `crates/umc-bundle/src/replicate.rs`

- [ ] **Step 1: Write BUNDLE_ACK mapping**

`crates/umc-bundle/src/ack.rs`:

```rust
//! BUNDLE_ACK status mapping (wire-format.md §50, bundles.md §13).
use crate::manager::BundleStatus;

/// Status values MUST match the wire registry (wire-format.md §50).
pub fn status_code(status: &BundleStatus) -> u64 {
    match status {
        BundleStatus::Received => 0,
        BundleStatus::CustodyAccepted => 1,
        BundleStatus::Forwarded => 2,
        BundleStatus::Delivered => 3,
        BundleStatus::Rejected => 4,
        BundleStatus::Expired => 5,
        BundleStatus::Evicted => 6,
    }
}

pub fn status_from_code(code: u64) -> Option<BundleStatus> {
    match code {
        0 => Some(BundleStatus::Received),
        1 => Some(BundleStatus::CustodyAccepted),
        2 => Some(BundleStatus::Forwarded),
        3 => Some(BundleStatus::Delivered),
        4 => Some(BundleStatus::Rejected),
        5 => Some(BundleStatus::Expired),
        6 => Some(BundleStatus::Evicted),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_wire_registry() {
        assert_eq!(status_code(&BundleStatus::Received), 0);
        assert_eq!(status_code(&BundleStatus::CustodyAccepted), 1);
        assert_eq!(status_code(&BundleStatus::Forwarded), 2);
        assert_eq!(status_code(&BundleStatus::Delivered), 3);
        assert_eq!(status_code(&BundleStatus::Rejected), 4);
        assert_eq!(status_code(&BundleStatus::Expired), 5);
        assert_eq!(status_code(&BundleStatus::Evicted), 6);
    }

    #[test]
    fn round_trip() {
        for code in 0..=6 {
            assert_eq!(status_from_code(code).map(|s| status_code(&s)), Some(code));
        }
        assert!(status_from_code(7).is_none());
    }
}
```

- [ ] **Step 2: Write replication policy**

`crates/umc-bundle/src/replicate.rs`:

```rust
//! Replication policy (bundles.md §15): bounded, explicit, quota-charged.
use crate::manager::{BundleManager, BundleStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicationDecision {
    Replicate,
    DoNotReplicate,
    Skip,
}

/// Replication is governed by the DO_NOT_REPLICATE flag, the replication
/// limit, sender policy, and storage pressure (bundles.md §15.1).
pub fn decide_replication(manager: &BundleManager, id: &[u8; 32], do_not_replicate: bool, storage_pressure_high: bool) -> ReplicationDecision {
    if do_not_replicate {
        return ReplicationDecision::DoNotReplicate;
    }
    let Some(record) = manager.record(id) else {
        return ReplicationDecision::Skip;
    };
    if record.replication_count >= crate::manager::DEFAULT_MAX_REPLICATION {
        return ReplicationDecision::DoNotReplicate;
    }
    if record.status == BundleStatus::Delivered {
        return ReplicationDecision::Skip;
    }
    if storage_pressure_high && record.priority == 0 {
        return ReplicationDecision::Skip;
    }
    ReplicationDecision::Replicate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{BundleManager, DEFAULT_LIFETIME_MS};
    use umc_storage::objects::ObjectStore;
    use umc_storage::quota::{Profile, QuotaAccount};

    fn manager() -> BundleManager {
        let dir = std::env::temp_dir().join(format!("umc-repl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        BundleManager::new(ObjectStore::open(dir).unwrap(), QuotaAccount::new(Profile::Standard, 0, 1_048_576))
    }

    #[test]
    fn flags_and_limits_govern() {
        let mut m = manager();
        let id = m.admit(b"p", b"s", b"d", 1, DEFAULT_LIFETIME_MS, 3, false, umc_types::runtime::Instant(0)).unwrap();
        assert_eq!(decide_replication(&m, &id, false, false), ReplicationDecision::Replicate);
        assert_eq!(decide_replication(&m, &id, true, false), ReplicationDecision::DoNotReplicate);
    }

    #[test]
    fn delivered_bundles_skip() {
        let mut m = manager();
        let id = m.admit(b"p", b"s", b"d", 1, DEFAULT_LIFETIME_MS, 3, false, umc_types::runtime::Instant(0)).unwrap();
        m.set_status(&id, BundleStatus::Delivered).unwrap();
        assert_eq!(decide_replication(&m, &id, false, false), ReplicationDecision::Skip);
    }

    #[test]
    fn pressure_sheds_low_priority() {
        let mut m = manager();
        let id = m.admit(b"p", b"s", b"d", 0, DEFAULT_LIFETIME_MS, 3, false, umc_types::runtime::Instant(0)).unwrap();
        assert_eq!(decide_replication(&m, &id, false, true), ReplicationDecision::Skip);
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-bundle`
Expected: PASS (20 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-bundle/src/ack.rs crates/umc-bundle/src/replicate.rs
git commit -m "feat(bundle): acknowledgements and replication policy"
```

---

### Task 6: Integration test — one-hop delayed delivery

**Files:**
- Create: `tests/phase6/Cargo.toml`
- Create: `tests/phase6/tests/delayed_delivery.rs`

- [ ] **Step 1: Test crate manifest**

`tests/phase6/Cargo.toml`:

```toml
[package]
name = "phase6-tests"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
umc-bundle = { path = "../../crates/umc-bundle" }
umc-crypto = { path = "../../crates/umc-crypto" }
umc-storage = { path = "../../crates/umc-storage" }
umc-types = { path = "../../crates/umc-types" }

[lints]
workspace = true
```

- [ ] **Step 2: Write the delayed-delivery test**

`tests/phase6/tests/delayed_delivery.rs`:

```rust
//! Phase 6 success criterion: a bundle created while the destination is
//! unreachable is delivered when connectivity returns.
use umc_bundle::envelope::{open_bundle, seal_bundle};
use umc_bundle::expiry::evict_expired;
use umc_bundle::forward::{handoff, select_for_contact, Contact};
use umc_bundle::id::bundle_id;
use umc_bundle::manager::{BundleManager, BundleStatus, DEFAULT_LIFETIME_MS};
use umc_crypto::signatures::StaticHandshakeKeyPair;
use umc_storage::objects::ObjectStore;
use umc_storage::quota::{Profile, QuotaAccount};
use umc_types::runtime::{Duration, Instant};

fn manager() -> BundleManager {
    let dir = std::env::temp_dir().join(format!("umc-phase6-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    BundleManager::new(ObjectStore::open(dir).unwrap(), QuotaAccount::new(Profile::Standard, 0, 16 * 1024 * 1024))
}

#[test]
fn one_hop_delayed_delivery() {
    let sender = StaticHandshakeKeyPair::generate();
    let destination = StaticHandshakeKeyPair::generate();
    let now = Instant(0);

    // 1. Sender seals a bundle to the destination (storage node never sees it).
    let envelope = seal_bundle(&sender, &destination.public(), b"delayed message");
    let destination_hint = b"dest-token";
    let id = bundle_id(&envelope, destination_hint);

    // 2. Storage node admits it while the destination is unreachable.
    let mut store = manager();
    let admitted = store.admit(&envelope.encrypted_payload, b"sender", destination_hint, 1, DEFAULT_LIFETIME_MS, 3, false, now).unwrap();
    assert_eq!(admitted, id, "bundle ID is content-derived and stable");
    assert_eq!(store.record(&id).unwrap().status, BundleStatus::Received);

    // 3. Disconnection: time passes, the bundle is still valid but unforwarded.
    let mid = now + Duration::from_millis(60_000);
    assert_eq!(evict_expired(&mut store, mid), 0);

    // 4. Connectivity returns: a contact for the destination appears.
    let contact = Contact { destination_hint: destination_hint.to_vec(), peer: b"destination-adjacent".to_vec(), expires_at: mid + Duration::from_millis(30_000) };
    let selected = select_for_contact(&store, &contact, mid).unwrap();
    assert_eq!(selected.len(), 1);

    // 5. Handoff; the destination-facing node opens the envelope.
    let result = handoff(&mut store, &id, b"destination-adjacent").unwrap();
    let opened = open_bundle(&destination, &envelope).unwrap();
    assert_eq!(opened, b"delayed message");
    assert_eq!(result.payload, envelope.encrypted_payload, "storage node forwards ciphertext, never plaintext");
    assert_eq!(store.record(&id).unwrap().status, BundleStatus::Forwarded);
}

#[test]
fn bundle_survives_longer_than_any_session() {
    // Bundles outlive live sessions by design (bundles.md §21.1).
    let mut store = manager();
    let id = store.admit(b"persist me", b"s", b"d", 1, DEFAULT_LIFETIME_MS, 3, false, Instant(0)).unwrap();
    // A live session would have timed out (max 30s idle per session.md); the
    // bundle is still stored an hour later.
    assert_eq!(evict_expired(&mut store, Instant(3_600_000)), 0);
    assert!(store.get_payload(&id).is_ok());
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p phase6-tests`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add tests/phase6
git commit -m "test(phase6): one-hop delayed delivery"
```

---

### Task 7: Phase 6 completion gate

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
- [x] Phase 5: local mesh
- [x] Phase 6: store-and-forward — experimental bundles, one-hop delayed delivery
- [ ] Phase 7: adversarial resilience
```

- [ ] **Step 3: Verify Phase 6 success criteria from `core.md` §64**

Checklist:

- [ ] Bundle storage (content-addressed, quota-bounded)
- [ ] Expiration (monotonic, eviction order)
- [ ] Replication limits (DO_NOT_REPLICATE, count caps, pressure)
- [ ] Intermittent delivery (one-hop delayed delivery test)
- [ ] Bundle envelope encryption (sealed to destination)
- [ ] Deduplication by Bundle ID
- [ ] BUNDLE_ACK status mapping (wire registry)
- [ ] A delayed bundle is delivered after connectivity returns (success criterion 8)
- [ ] Experimental marker present; no custody transfer, no epidemic replication

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: phase 6 complete"
```

---

## Phase 6 self-review

**Spec coverage:** `bundles.md` §7 (envelope) → Task 1; §6 (identifiers) → Task 2; §8-10 (frame, storage, quotas) → Task 3; §11, §19 (expiration, eviction) → Task 4; §16-17 (forwarding, contacts) → Task 4; §13 (acknowledgements) → Task 5; §15 (replication) → Task 5; `storage.md` §11-12 (objects, bundle layout) → Task 3.

**Known deferrals (per `decisions.md` §9 and `bundles.md` §25):** custody transfer, epidemic replication, multi-carrier physical movement routing, strong delivery receipts, global bundle routing, intermittent-contact route selection algorithm, bundle segmentation extension, `HIGH_SENSITIVITY` retention policy.
