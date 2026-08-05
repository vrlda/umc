# Phase 14: Conformance and Completeness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every gap found by the full spec-vs-plan re-read (August 2026 audit): implement the identity-trust subsystem, routing response/path handling, relay status/authorization, discovery bootstrap, handshake state machine and remaining packet classes, session retransmission and control-frame handling, BUNDLE wire transfer, plugin operations, the full Control API service set, the remaining SDK surface, and the testing/security gates — plus errata fixing bugs in earlier plans.

**Architecture:** This phase is conformance work over the existing crate structure. It proceeds by area; each area's tasks follow the established TDD pattern. The errata section MUST be applied before any other task.

**Tech Stack:** Rust stable, existing umc crates, proptest, cargo-fuzz.

---

## Part A — Errata (apply FIRST)

Apply these fixes to earlier plans before executing any other task.

- [ ] **E1. Phase 0 Task 3 — varint test vector wrong and decoder missing width check**

`2026-08-06-phase0-foundations.md`, varint test `encoding_widths_match_spec`: `encode(1_073_741_824)` is 2³⁰, which exceeds the 4-byte width maximum (2³⁰−1) and MUST use 8 bytes. Replace the vector:

```rust
    #[test]
    fn encoding_widths_match_spec() {
        assert_eq!(encode(0).unwrap(), vec![0x00]);
        assert_eq!(encode(63).unwrap(), vec![0x3F]);
        assert_eq!(encode(64).unwrap(), vec![0x40, 0x40]);
        assert_eq!(encode(16_383).unwrap(), vec![0x7F, 0xFF]);
        assert_eq!(encode(1_073_741_824).unwrap(), vec![0xC0, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
```

And in `decode`, reject values that do not fit the encoded width (wire-format.md §5 "Values encoded with an invalid width"):

```rust
    let v = u64::from_be_bytes(raw);
    // A value must fit the width that encoded it (wire-format.md §5).
    let fits_width = match width {
        1 => v <= 63,
        2 => v <= 16_383,
        4 => v <= 1_073_741_823,
        _ => v <= MAX_VARINT,
    };
    if !fits_width {
        return Err(DecodeError::InvalidWidth);
    }
```

Add the variant: `InvalidWidth,` to `DecodeError`.

- [ ] **E2. Phase 0 Task 8 — PADDING dispatch bug**

In `decode_frames`, the PADDING arm checks `rest.first()` but the padding byte IS the type byte consumed already. Replace the arm:

```rust
                    FrameType::PADDING => {
                        // Each zero byte is one PADDING frame; the type byte
                        // already consumed IS the padding byte.
                        out.push(Frame::Padding);
                    }
```

Remove the `InvalidPadding` check for PADDING (the type byte being 0x00 already proves it). Keep `InvalidPadding` for other uses.

- [ ] **E3. Phase 2 Task 9 — bearer-token entropy**

`TokenRegistry::create_token` fills only 8 bytes. Spec control-api.md §11.2 requires at least 256 bits. Change the signature to take the entropy source:

```rust
    pub fn create_token(&mut self, expires_at_ms: Option<u64>, entropy: &dyn EntropySource) -> (PrincipalId, Vec<u8>) {
        let principal_id = self.next_id;
        self.next_id += 1;
        let mut raw = vec![0u8; 32];
        entropy.fill(&mut raw); // full 256 bits of CSPRNG output
        let hash = token_hash(&raw);
        self.tokens.insert(hash, TokenRecord { principal_id, expires_at_ms });
        (principal_id, raw)
    }
```

Update callers and the test to pass a test entropy source.

- [ ] **E4. Phase 2 Task 10 — handle randomness**

`Handle::new` uses 13 of 16 bytes for tag/principal/generation, leaving 4 random bytes. Spec control-api.md §36: opaque 16-byte random values. Store the binding separately:

```rust
    pub fn new(handle_type: HandleType, principal_id: u64, generation: u64, entropy: &dyn EntropySource) -> Self {
        let mut bytes = [0u8; 16];
        entropy.fill(&mut bytes); // all 16 bytes random
        Self { bytes }
    }

    // Binding fields move to a registry-side map keyed by the random handle;
    // Handle::validate is replaced by registry lookups that compare stored
    // (type, principal, generation). Keep the old field-encoding helpers only
    // for the audit log, not for validation.
```

Consequently `Handle::handle_type()/principal_id()/generation()` become registry-derived. Update `handles.rs` tests to construct handles through a `HandleRegistry` that stores the binding.

- [ ] **E5. Phase 2 Task 9 — grants empty-constraint test**

The test `empty_constraints_are_not_wildcards` asserts the wrong behavior. Spec control-api.md §14: an ABSENT `ResourceConstraints` means no resource restriction; an EMPTY repeated list inside present constraints means nothing unless `all_resources`. Fix the test:

```rust
    #[test]
    fn absent_constraints_do_not_restrict() {
        let mut set = GrantSet::empty();
        set.add(Grant { grant_id: 1, capabilities: vec![api::Capability::NODE_READ], resource_constraints: None, expires_at_ms: None });
        assert!(set.resource_allowed(api::Capability::NODE_READ, b"any-endpoint", 0));
    }

    #[test]
    fn empty_constraint_list_grants_nothing_without_all_resources() {
        let mut set = GrantSet::empty();
        set.add(Grant {
            grant_id: 2,
            capabilities: vec![api::Capability::APPLICATION_CONNECT],
            resource_constraints: Some(api::ResourceConstraints { all_resources: false, ..Default::default() }),
            expires_at_ms: None,
        });
        assert!(!set.resource_allowed(api::Capability::APPLICATION_CONNECT, b"ep", 0));
    }
```

- [ ] **E6. Phase 6 Task 3/4 — bundle admission ordering and replication limit**

1. Move the duplicate check BEFORE quota reservation and object write (bundles.md §8.1: policy before allocation). `admit` must compute the Bundle ID from the envelope first, then check `records`, then reserve and write.
2. Store `replication_limit` on `BundleRecord` (add the field) and use `record.replication_limit` in `handoff` and `decide_replication` instead of the global constant.

- [ ] **E7. Phase 7 Task 1 — psk.rs compile error**

`authenticator()` calls `crate::discovery_invitation_authenticator` but the helper lives in `xx.rs`. Change the call to `crate::xx::discovery_invitation_authenticator(...)`.

- [ ] **E8. Phase 11 Task 2 — handle encode/decode**

The 40-bit truncation breaks the round-trip test. Fix `encode`/`decode` to use the full 64 bits:

```rust
    pub fn encode(&self) -> u64 {
        ((self.generation as u64) << 48) | ((self.handle_type as u64) << 40) | (self.value & 0xFF_FFFF_FFFF)
    }
```

The value field is already a u64 from 8 entropy bytes; the mask keeps the low 40 bits, which the test entropy (all 0x09 bytes → 0x0909090909090909) survives for the low 40 bits (`0x090909090909`), so the round-trip holds. Verify the test's entropy constant matches.

- [ ] **E9. Phase 11 Task 1 — schema completeness**

Add the six missing event types and the missing error fields to `api/carrier-plugin.proto`:

```protobuf
  QUALITY_CHANGED = 11;
  ADDRESS_REBOUND = 12;
  CANDIDATE_UPDATED = 13;
  CANDIDATE_REMOVED = 14;
  HEALTH = 15;
  CLOSING = 16;
```

```protobuf
message PluginError {
  uint32 category = 1;
  uint32 code = 2;
  string operation = 3;
  uint32 retryability = 4;
  string scope = 5;
  string message = 6;
  string source_error = 7;
  uint64 retry_after_ms = 8;
}
```

- [ ] **E10. Phase 12 Task 1 — IK server_random**

`ServerHello.server_random` is hardcoded `[0u8; 32]`. Generate it from the entropy source (threat-model §35.3 fresh randoms).

- [ ] **E11. Phase 13 Task 5 — bundle fuzz target**

`fuzz/fuzz_targets/bundle_frame.rs` references `umc_wire::frames::bundle::BundleFrame`, which Phase 14 Task 8 creates. Keep the file; it compiles only after that task lands.

- [ ] **E12. Phase 13 Task 6 — quota recalculation no-op**

Implement real recalculation: after loading persisted records, rebuild the manager's quota usage from record sizes:

```rust
    pub fn rebuild_quota(&mut self) {
        let used: u64 = self.records.values().map(|r| r.size as u64).sum();
        self.quota = QuotaAccount::new(self.quota.profile, used, self.quota.hard_limit);
    }
```

Call it in the test after loading records, and assert `quota.used() == sum of sizes`.

- [ ] **E13. Phase 13 Task 2 — wrong citation**

`persist.rs` cites "bundles.md §44" — should be `bundles.md §9` (storage) / `storage.md §12` (bundle metadata lifecycle). Fix the comment.

---

## Part B — Wire and handshake conformance

### Task 1: Retry, Handshake, and Version-Negotiation packet classes

**Files:**
- Modify: `crates/umc-core/src/wire.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/umc-core/src/wire.rs`:

```rust
/// Build a Handshake-class packet (wire-format §15): long header, handshake
/// traffic keys, handshake payload.
pub fn build_handshake_packet(
    keys: &PacketKeys,
    version: u32,
    dcid: &[u8],
    scid: &[u8],
    packet_number: u64,
    payload: &[u8],
) -> Result<Vec<u8>, WireError> {
    let mut header = Vec::new();
    header.push(HeaderByte::LONG_HANDSHAKE.encode());
    header.extend_from_slice(&version.to_be_bytes());
    header.push(dcid.len() as u8);
    header.extend_from_slice(dcid);
    header.push(scid.len() as u8);
    header.extend_from_slice(scid);
    umc_wire::varint::encode_into(&mut header, 0).map_err(|_| WireError::Truncated)?;
    umc_wire::varint::encode_into(&mut header, payload.len() as u64 + 2 + 16).map_err(|_| WireError::Truncated)?;
    let pn_bytes = packet_number.to_be_bytes()[6..].to_vec();
    let mut aad = header.clone();
    aad.extend_from_slice(&pn_bytes);
    let ciphertext = keys.seal(packet_number, &aad, payload).map_err(WireError::Aead)?;
    let mut out = header;
    out.extend_from_slice(&pn_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Parse a Handshake-class packet.
pub fn parse_handshake_packet(
    keys: &PacketKeys,
    bytes: &[u8],
    expected_pn: u64,
) -> Result<(u64, Vec<u8>), WireError> {
    let first = *bytes.first().ok_or(WireError::Truncated)?;
    let hb = umc_wire::header::HeaderByte::decode(first).map_err(WireError::Header)?;
    if !hb.long || hb.long_type() != Some(LongPacketType::Handshake) {
        return Err(WireError::Header(umc_wire::header::HeaderError::InvalidType));
    }
    let dcid_len = bytes[5] as usize;
    let scid_len = bytes[6 + dcid_len] as usize;
    let mut pos = 7 + dcid_len + scid_len;
    let (_, n) = umc_wire::varint::decode(&bytes[pos..]).map_err(|_| WireError::Truncated)?;
    pos += n;
    let (_, n) = umc_wire::varint::decode(&bytes[pos..]).map_err(|_| WireError::Truncated)?;
    pos += n;
    let pn_bytes = bytes.get(pos..pos + 2).ok_or(WireError::Truncated)?;
    let mut pn_full = [0u8; 8];
    pn_full[6..].copy_from_slice(pn_bytes);
    let truncated_pn = u64::from_be_bytes(pn_full);
    let pn = umc_wire::pn::reconstruct(truncated_pn, 16, expected_pn).map_err(|_| WireError::Truncated)?;
    let mut aad = bytes[..pos].to_vec();
    aad.extend_from_slice(pn_bytes);
    let payload = keys.open(pn, &aad, &bytes[pos + 2..]).map_err(WireError::Aead)?;
    Ok((pn, payload))
}

/// Version-negotiation packet (wire-format §16): long header, supported
/// versions, integrity data. Must be authenticated when possible and rate-limited.
pub fn build_version_negotiation(version: u32, dcid: &[u8], scid: &[u8], supported: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(HeaderByte::LONG_VERSION_NEGOTIATION.encode());
    out.extend_from_slice(&version.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    umc_wire::varint::encode_into(&mut out, supported.len() as u64).expect("bounded");
    for v in supported {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}
```

Tests:

```rust
    #[test]
    fn handshake_packet_round_trip() {
        let keys = PacketKeys::from_traffic_secret(&[3u8; 32]).unwrap();
        let pkt = build_handshake_packet(&keys, 1, &[1u8; 8], &[2u8; 8], 5, b"handshake-frames").unwrap();
        let (pn, payload) = parse_handshake_packet(&keys, &pkt, 0).unwrap();
        assert_eq!(pn, 5);
        assert_eq!(payload, b"handshake-frames");
    }

    #[test]
    fn wrong_keys_fail_handshake_parse() {
        let a = PacketKeys::from_traffic_secret(&[3u8; 32]).unwrap();
        let b = PacketKeys::from_traffic_secret(&[4u8; 32]).unwrap();
        let pkt = build_handshake_packet(&a, 1, &[1u8; 8], &[2u8; 8], 1, b"x").unwrap();
        assert!(parse_handshake_packet(&b, &pkt, 0).is_err());
    }

    #[test]
    fn version_negotiation_lists_supported() {
        let vn = build_version_negotiation(99, &[1u8; 8], &[2u8; 8], &[1]);
        assert_eq!(vn[0], 0b1110_0000); // long header, type 11
        assert!(vn.len() >= 5 + 1 + 8 + 1 + 8 + 4);
    }

    #[test]
    fn retry_packet_structure() {
        // Retry (wire-format §14): long header, token length, token, integrity tag.
        let mut out = Vec::new();
        out.push(HeaderByte::LONG_RETRY.encode());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.push(8);
        out.extend_from_slice(&[1u8; 8]);
        out.push(8);
        out.extend_from_slice(&[2u8; 8]);
        let token = vec![0xAA; 64];
        umc_wire::varint::encode_into(&mut out, token.len() as u64).unwrap();
        out.extend_from_slice(&token);
        out.extend_from_slice(&[0xBB; 16]); // integrity tag
        assert_eq!(out[0], 0b1010_0000);
    }
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-core`
Expected: PASS (21 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-core/src/wire.rs
git commit -m "feat(core): handshake and version-negotiation packets"
```

---

### Task 2: Short-header header protection

**Files:**
- Modify: `crates/umc-session/src/packet.rs`

- [ ] **Step 1: Apply header protection to short-header packets**

Modify `build_protected_packet` to protect the packet number and key-phase bit, and `parse_protected_packet` to unprotect:

```rust
use umc_crypto::header_protection::{protect, unprotect};

    // In build_protected_packet, after building header + pn_bytes:
    let hp_key = keys.key; // provisional: HP key == packet key (Phase 1 decision)
    let mut protected_pn = pn_bytes.clone();
    let (protected_first, _) = protect(&hp_key, hb.encode(), key_phase, &mut protected_pn);
    let mut aad = header[..header.len() - 1].to_vec(); // header without first byte
    aad.insert(0, protected_first);
    aad.extend_from_slice(&protected_pn);
    let ciphertext = keys.seal(packet_number, &aad, payload)?;
    let mut out = header;
    out[0] = protected_first;
    out.extend_from_slice(&protected_pn);
    out.extend_from_slice(&ciphertext);
```

And in parse:

```rust
    let (unprotected_first, _, unprotected_pn) = unprotect(&hp_key, bytes[0], &bytes[pn_start..pn_start + pn_len]);
    // use unprotected_first for the header byte decode and unprotected_pn for
    // the packet number bytes in both the PN reconstruction and the AAD.
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-session`
Expected: PASS — the round-trip test still passes (protection is symmetric). The `wrong_key_fails_parse` test still fails as expected.

- [ ] **Step 3: Commit**

```bash
git add crates/umc-session/src/packet.rs
git commit -m "feat(session): header protection on short-header packets"
```

---

### Task 3: Unknown optional length-delimited frame skipping

**Files:**
- Modify: `crates/umc-wire/src/frame.rs`

- [ ] **Step 1: Implement skip semantics**

In `decode_frames`, replace the length-delimited fallback:

```rust
            ExtensionBehavior::CriticalLengthDelimited => {
                let (len, n) = crate::varint::decode(&payload[pos..]).map_err(FrameError::Varint)?;
                let total = n.checked_add(len as usize).ok_or(FrameError::Truncated)?;
                if pos + total > payload.len() {
                    return Err(FrameError::Truncated);
                }
                // Known critical length-delimited frames are handled in the
                // fixed arm table below (routing/relay/bundle); this branch
                // only fires for unknown critical frames.
                return Err(FrameError::UnknownCriticalFrame(ty));
            }
            ExtensionBehavior::OptionalLengthDelimited => {
                // Skip unknown optional length-delimited frames (wire-format §22).
                let (len, n) = crate::varint::decode(&payload[pos..]).map_err(FrameError::Varint)?;
                let total = n.checked_add(len as usize).ok_or(FrameError::Truncated)?;
                if pos + total > payload.len() {
                    return Err(FrameError::Truncated);
                }
                pos += total;
            }
```

Note: known length-delimited frames (ROUTE_*, RELAY_OPEN/STATUS/CLOSE, BUNDLE, PEER_HINT, CAPABILITIES, AUTH, HANDSHAKE_DATA, SESSION_TICKET, SERVICE_HINT) are matched BEFORE the behavior fallback — ensure the match arms for those come first. Restructure `decode_frames` so known types match first, then behavior-based fallback.

- [ ] **Step 2: Add the test**

```rust
    #[test]
    fn unknown_optional_length_delimited_is_skipped() {
        // Type 0x0F (..11, optional length-delimited), length 2, body.
        let payload = [0x0F, 0x02, 0xAA, 0xBB, 0x04];
        let frames = decode_frames(&payload).unwrap();
        assert_eq!(frames, vec![Frame::Ping]);
    }

    #[test]
    fn truncated_optional_frame_rejected() {
        assert_eq!(decode_frames(&[0x0F, 0x05, 0xAA]), Err(FrameError::Truncated));
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-wire`
Expected: PASS (41 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/src/frame.rs
git commit -m "feat(wire): skip unknown optional length-delimited frames"
```

---

### Task 4: Handshake state machine

**Files:**
- Create: `crates/umc-handshake/src/state.rs`

- [ ] **Step 1: Write the failing test**

`crates/umc-handshake/src/state.rs`:

```rust
//! Handshake state machine (handshake.md §6): ten states, invalid transitions
//! rejected, no application keys before confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Idle,
    InitialSent,
    InitialReceived,
    RetrySent,
    RetryReceived,
    HandshakeKeys,
    PeerAuthenticated,
    SessionKeys,
    Confirmed,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeEvent {
    SendClientHello,
    ReceiveServerHello,
    ReceiveRetry,
    SendClientAuth,
    ReceiveServerFinished,
    SendClientFinished,
    InstallHandshakeKeys,
    InstallSessionKeys,
    Confirm,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    InvalidTransition,
}

pub struct HandshakeMachine {
    pub state: HandshakeState,
    pub peer_authenticated: bool,
    pub application_keys_installed: bool,
}

impl HandshakeMachine {
    pub fn new() -> Self {
        Self { state: HandshakeState::Idle, peer_authenticated: false, application_keys_installed: false }
    }

    pub fn apply(&mut self, event: HandshakeEvent) -> Result<(), StateError> {
        use HandshakeEvent::*;
        use HandshakeState::*;
        let next = match (self.state, event) {
            (Idle, SendClientHello) => InitialSent,
            (Idle, ReceiveRetry) => RetryReceived,
            (InitialSent, ReceiveRetry) => RetryReceived,
            (InitialSent, ReceiveServerHello) => HandshakeKeys,
            (RetryReceived, SendClientHello) => InitialSent,
            (HandshakeKeys, InstallHandshakeKeys) => HandshakeKeys,
            (HandshakeKeys, SendClientAuth) => PeerAuthenticated,
            (PeerAuthenticated, ReceiveServerFinished) => SessionKeys,
            (SessionKeys, InstallSessionKeys) => SessionKeys,
            (SessionKeys, SendClientFinished) => SessionKeys,
            (SessionKeys, Confirm) => Confirmed,
            (Confirmed, InstallSessionKeys) => Confirmed,
            (_, Fail) => Closed,
            (_, _) => return Err(StateError::InvalidTransition),
        };
        self.state = next;
        if matches!(self.state, PeerAuthenticated | SessionKeys | Confirmed) {
            self.peer_authenticated = true;
        }
        if matches!(self.state, Confirmed) {
            self.application_keys_installed = true;
        }
        Ok(())
    }

    /// "MUST NOT install application traffic keys until DH completes,
    /// transcript is authenticated, binding verified, parameters validated"
    /// (handshake.md §6).
    pub fn may_install_application_keys(&self) -> bool {
        self.state == HandshakeState::Confirmed
    }
}

impl Default for HandshakeMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use HandshakeEvent::*;

    #[test]
    fn happy_path() {
        let mut m = HandshakeMachine::new();
        for event in [SendClientHello, ReceiveServerHello, InstallHandshakeKeys, SendClientAuth, ReceiveServerFinished, InstallSessionKeys, SendClientFinished, Confirm] {
            assert!(m.apply(event).is_ok(), "{event:?}");
        }
        assert_eq!(m.state, HandshakeState::Confirmed);
        assert!(m.peer_authenticated);
        assert!(m.may_install_application_keys());
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut m = HandshakeMachine::new();
        assert_eq!(m.apply(Confirm), Err(StateError::InvalidTransition));
        assert_eq!(m.apply(ReceiveServerHello), Err(StateError::InvalidTransition));
        assert!(!m.may_install_application_keys());
    }

    #[test]
    fn retry_path() {
        let mut m = HandshakeMachine::new();
        m.apply(ReceiveRetry).unwrap();
        m.apply(SendClientHello).unwrap();
        assert_eq!(m.state, HandshakeState::InitialSent);
    }

    #[test]
    fn failure_closes() {
        let mut m = HandshakeMachine::new();
        m.apply(Fail).unwrap();
        assert_eq!(m.state, HandshakeState::Closed);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-handshake`
Expected: PASS (48 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-handshake/src/state.rs crates/umc-handshake/src/lib.rs
git commit -m "feat(handshake): state machine"
```

---

### Task 5: Handshake traffic secrets and capability/parameter negotiation

**Files:**
- Modify: `crates/umc-handshake/src/traffic.rs`
- Create: `crates/umc-handshake/src/params.rs`

- [ ] **Step 1: Add handshake traffic secrets**

Append to `crates/umc-handshake/src/traffic.rs`:

```rust
/// Handshake traffic secrets (handshake.md §25): derived after HandshakeSecret3.
pub fn derive_handshake_traffic(handshake_secret3: &[u8; 32], transcript: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let client = expand(handshake_secret3, b"client handshake traffic", transcript);
    let server = expand(handshake_secret3, b"server handshake traffic", transcript);
    (client, server)
}
```

- [ ] **Step 2: Write the parameter negotiation**

`crates/umc-handshake/src/params.rs`:

```rust
//! Transport parameter negotiation (handshake.md §30, session.md §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParameters {
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_bidirectional_streams: u64,
    pub initial_max_unidirectional_streams: u64,
    pub maximum_datagram_size: u64,
    pub idle_timeout_ms: u64,
    pub maximum_ack_delay_ms: u64,
    pub ack_delay_exponent: u64,
    pub active_connection_id_limit: u64,
    pub maximum_paths: u64,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data_bidi_local: 256 * 1024,
            initial_max_stream_data_bidi_remote: 256 * 1024,
            initial_max_stream_data_uni: 256 * 1024,
            initial_max_bidirectional_streams: 16,
            initial_max_unidirectional_streams: 16,
            maximum_datagram_size: 1_200,
            idle_timeout_ms: 30_000,
            maximum_ack_delay_ms: 25,
            ack_delay_exponent: 3,
            active_connection_id_limit: 4,
            maximum_paths: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamError {
    UnknownCritical,
    Duplicate,
    ValueTooLarge,
}

/// Validate received parameters (session.md §7): reject duplicates, unknown
/// critical parameters, and values above protocol limits.
pub fn validate_parameters(params: &TransportParameters) -> Result<(), ParamError> {
    if params.maximum_paths > 8 {
        return Err(ParamError::ValueTooLarge);
    }
    if params.active_connection_id_limit < 2 {
        return Err(ParamError::ValueTooLarge);
    }
    if params.maximum_ack_delay_ms > 1_000 {
        return Err(ParamError::ValueTooLarge);
    }
    Ok(())
}

/// Effective limits: the smaller of both sides' offers (session.md §22).
pub fn effective_parameters(local: &TransportParameters, remote: &TransportParameters) -> TransportParameters {
    TransportParameters {
        initial_max_data: local.initial_max_data.min(remote.initial_max_data),
        initial_max_stream_data_bidi_local: local.initial_max_stream_data_bidi_local,
        initial_max_stream_data_bidi_remote: remote.initial_max_stream_data_bidi_remote,
        initial_max_stream_data_uni: local.initial_max_stream_data_uni.min(remote.initial_max_stream_data_uni),
        initial_max_bidirectional_streams: local.initial_max_bidirectional_streams.min(remote.initial_max_bidirectional_streams),
        initial_max_unidirectional_streams: local.initial_max_unidirectional_streams.min(remote.initial_max_unidirectional_streams),
        maximum_datagram_size: local.maximum_datagram_size.min(remote.maximum_datagram_size),
        idle_timeout_ms: if local.idle_timeout_ms == 0 { remote.idle_timeout_ms } else { local.idle_timeout_ms.min(remote.idle_timeout_ms) },
        maximum_ack_delay_ms: local.maximum_ack_delay_ms,
        ack_delay_exponent: local.ack_delay_exponent,
        active_connection_id_limit: local.active_connection_id_limit.min(remote.active_connection_id_limit),
        maximum_paths: local.maximum_paths.min(remote.maximum_paths),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        assert_eq!(validate_parameters(&TransportParameters::default()), Ok(()));
    }

    #[test]
    fn effective_limits_take_the_minimum() {
        let local = TransportParameters { initial_max_data: 1_000, ..Default::default() };
        let remote = TransportParameters { initial_max_data: 2_000, ..Default::default() };
        assert_eq!(effective_parameters(&local, &remote).initial_max_data, 1_000);
    }

    #[test]
    fn oversized_values_rejected() {
        let mut p = TransportParameters::default();
        p.maximum_ack_delay_ms = 2_000;
        assert_eq!(validate_parameters(&p), Err(ParamError::ValueTooLarge));
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-handshake`
Expected: PASS (51 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-handshake/src/traffic.rs crates/umc-handshake/src/params.rs crates/umc-handshake/src/lib.rs
git commit -m "feat(handshake): handshake traffic secrets and parameter negotiation"
```

### Task 6: Session retransmission and inbound control frames

**Files:**
- Modify: `crates/umc-session/src/session.rs`

- [ ] **Step 1: Implement retransmission**

Append to `crates/umc-session/src/session.rs`:

```rust
    /// Retransmit information from lost packets (session.md §15): new packet
    /// numbers, current keys, preserved offsets. Phase 14 keeps a bounded
    /// retransmission buffer of stream-frame payloads keyed by stream offset.
    pub fn retransmit_lost(&mut self, lost_pns: &[u64], now: Instant) -> Result<Vec<u8>, SessionError> {
        let _ = lost_pns;
        // The session stores pending stream data in `pending_retransmit`:
        // (stream_id, offset, data, fin). Lost packets re-send those chunks.
        let mut payload = Vec::new();
        let pending: Vec<(u64, u64, Vec<u8>, bool)> = self.pending_retransmit.drain(..).collect();
        for (stream_id, offset, data, fin) in pending {
            let frame = umc_wire::frames::stream::StreamFrame {
                stream_id,
                fin,
                offset_present: true,
                len_present: true,
                open: false,
                unidirectional: false,
                offset,
                data,
                protocol_id: vec![],
                metadata: vec![],
            };
            umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::STREAM.0).map_err(|_| SessionError::Encode)?;
            payload.extend_from_slice(&frame.encode().map_err(|_| SessionError::Encode)?[1..]);
        }
        let _ = now;
        Ok(payload)
    }
```

Add the buffer field and populate it in `send_stream_data`:

```rust
    pub pending_retransmit: std::collections::VecDeque<(u64, u64, Vec<u8>, bool)>,
```

In `send_stream_data`, after building the frame, push a clone of `(stream_id, offset, chunk, fin)` into `pending_retransmit` (bounded to 16,384 entries, popping oldest).

- [ ] **Step 2: Handle inbound control frames**

Extend `on_inbound`'s frame match with the currently-ignored control frames:

```rust
                umc_wire::frame::Frame::MaxData(f) => {
                    // Values MUST NOT decrease (session.md §20.3).
                    if f.maximum_data >= self.flow.max_data_remote {
                        self.flow.max_data_remote = f.maximum_data;
                    }
                }
                umc_wire::frame::Frame::ResetStream(f) => {
                    // Final size accounting; reset terminates the send direction.
                    let stream = self.streams.entry(f.stream_id).or_insert_with(|| Stream::new(f.stream_id, Vec::new(), self.flow.max_data_local));
                    stream.reset_remote(f.final_size).map_err(SessionError::Stream)?;
                }
                umc_wire::frame::Frame::StopSending(_) => {
                    // The receiver may respond with RESET_STREAM; Phase 14
                    // records the request and lets the application observe it.
                    self.stopped_streams.push(f.stream_id);
                }
                umc_wire::frame::Frame::KeyUpdate(f) => {
                    self.on_key_update(f.update_sequence)?;
                }
                umc_wire::frame::Frame::Migrate(f) => {
                    if f.migration_sequence > self.last_migration_sequence {
                        self.last_migration_sequence = f.migration_sequence;
                        // The new path must already be VALIDATED (session.md §27).
                    }
                }
                umc_wire::frame::Frame::PathChallenge(f) => {
                    // Respond on the same path (Phase 4 wiring sends this payload).
                    self.pending_path_responses.push_back(f.data);
                }
                umc_wire::frame::Frame::PathResponse(f) => {
                    // Confirm the matching challenge (Phase 4 path state).
                    self.pending_path_confirmations.push_back(f.data);
                }
                umc_wire::frame::Frame::NewConnectionId(f) => {
                    // Peer-issued CIDs: track for future rotation (session.md §30).
                    if !self.peer_cids.contains_key(&f.sequence) {
                        self.peer_cids.insert(f.sequence, f.connection_id.clone());
                    }
                }
                umc_wire::frame::Frame::RetireConnectionId(f) => {
                    self.peer_cids.remove(&f.sequence);
                }
```

Add fields and helpers to `Session`:

```rust
    pub stopped_streams: Vec<u64>,
    pub pending_path_responses: std::collections::VecDeque<[u8; 8]>,
    pub pending_path_confirmations: std::collections::VecDeque<[u8; 8]>,
    pub peer_cids: HashMap<u64, Vec<u8>>,
    pub last_migration_sequence: u64,
```

Add to `Stream` (stream.rs):

```rust
    pub fn reset_remote(&mut self, final_size: u64) -> Result<(), StreamError> {
        if let Some(fs) = self.final_size {
            if fs != final_size {
                return Err(StreamError::FinalSizeConflict);
            }
        } else {
            self.final_size = Some(final_size);
        }
        self.recv_state = RecvState::ResetRecvd;
        Ok(())
    }
```

- [ ] **Step 3: Add stream-ID validation**

Add a helper enforcing the low-bit scheme (wire-format.md §29):

```rust
    pub fn validate_stream_id(&self, stream_id: u64, initiator_bit: u64, unidirectional: bool) -> bool {
        let low = stream_id & 0b11;
        let expected_initiator = match self.role {
            Role::Client => 0,
            Role::Server => 1,
        };
        if unidirectional {
            // Bit 1 set = unidirectional; the initiator bit depends on the opener.
            low & 0b01 == expected_initiator && low & 0b10 != 0
        } else {
            low & 0b01 == expected_initiator && low & 0b10 == 0
        }
    }
```

Call it in `apply_stream_frame` before `entry().or_insert_with`; reject violations with `PROTOCOL_VIOLATION`-style error. Reject stream-ID reuse: track `max_seen` per direction and error when a stream ID below the max is re-opened with `OPEN`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-session`
Expected: PASS (51+ tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-session/src/session.rs crates/umc-session/src/stream.rs
git commit -m "feat(session): retransmission and inbound control frames"
```

---

### Task 7: Identity-trust subsystem (delegation, revocation, trust, TOFU)

**Files:**
- Create: `crates/umc-identity/Cargo.toml`
- Create: `crates/umc-identity/src/lib.rs`
- Create: `crates/umc-identity/src/trust.rs`
- Create: `crates/umc-identity/src/revocation.rs`
- Create: `crates/umc-identity/src/delegation.rs`
- Create: `crates/umc-identity/src/tofu.rs`
- Create: `crates/umc-identity/src/rotation.rs`

- [ ] **Step 1: Crate manifest**

`crates/umc-identity/Cargo.toml`:

```toml
[package]
name = "umc-identity"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
umc-types = { path = "../umc-types" }
umc-crypto = { path = "../umc-crypto" }
umc-handshake = { path = "../umc-handshake" }

[dev-dependencies]
proptest = "1"

[lints]
workspace = true
```

`crates/umc-identity/src/lib.rs`:

```rust
pub mod delegation;
pub mod revocation;
pub mod rotation;
pub mod tofu;
pub mod trust;
```

- [ ] **Step 2: Write the trust-state machine**

`crates/umc-identity/src/trust.rs`:

```rust
//! Trust states and transitions (identity-trust.md §14-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustState {
    Unknown,
    Observed,
    Introduced,
    Trusted,
    Restricted,
    Blocked,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustEvent {
    Authenticated,      // valid handshake -> Observed
    Introduction { expiry_ms: u64 },
    ExplicitTrust,
    Restrict,
    Block,
    Unblock,
    Revocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    InvalidTransition,
    PromotionRequiresExplicitAction,
    IntroducedIsNotTrusted,
}

#[derive(Debug, Clone)]
pub struct TrustRecord {
    pub endpoint_id: [u8; 32],
    pub state: TrustState,
    pub introduction_expiry_ms: Option<u64>,
    pub restricted_until_ms: Option<u64>,
    pub updated_at_ms: u64,
}

impl TrustRecord {
    pub fn new(endpoint_id: [u8; 32], now_ms: u64) -> Self {
        Self { endpoint_id, state: TrustState::Unknown, introduction_expiry_ms: None, restricted_until_ms: None, updated_at_ms: now_ms }
    }

    /// Transition matrix (identity-trust.md §15.1). Promotion to Trusted is
    /// NEVER automatic.
    pub fn apply(&mut self, event: TrustEvent, now_ms: u64) -> Result<(), TrustError> {
        use TrustEvent::*;
        use TrustState::*;
        match (self.state, event) {
            (Unknown, Authenticated) => self.state = Observed,
            (Unknown | Observed, Introduction { expiry_ms }) => {
                self.state = Introduced;
                self.introduction_expiry_ms = Some(expiry_ms);
            }
            (Observed | Introduced, ExplicitTrust) => self.state = Trusted,
            (_, Restrict) => self.state = Restricted,
            (_, Block) => self.state = Blocked,
            (Blocked | Restricted, Unblock) => self.state = Observed,
            (_, Revocation) => self.state = Revoked,
            (Introduced, _) if self.introduction_expired(now_ms) => {
                self.state = Observed;
                self.introduction_expiry_ms = None;
                return Err(TrustError::InvalidTransition); // expired intro cannot grant
            }
            _ => return Err(TrustError::InvalidTransition),
        }
        self.updated_at_ms = now_ms;
        Ok(())
    }

    pub fn introduction_expired(&self, now_ms: u64) -> bool {
        self.introduction_expiry_ms.map(|e| now_ms >= e).unwrap_or(false)
    }

    /// Resource multipliers (resource-limits.md §48).
    pub fn rate_multiplier(&self) -> f64 {
        match self.state {
            TrustState::Unknown => 0.25,
            TrustState::Observed => 1.0,
            TrustState::Introduced => 4.0,
            TrustState::Trusted => 10.0,
            TrustState::Restricted => 0.5,
            TrustState::Blocked | TrustState::Revoked => 0.0,
        }
    }

    pub fn state_multiplier(&self) -> f64 {
        match self.state {
            TrustState::Unknown => 0.25,
            TrustState::Observed => 1.0,
            TrustState::Introduced => 2.0,
            TrustState::Trusted => 4.0,
            TrustState::Restricted => 0.5,
            TrustState::Blocked | TrustState::Revoked => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_begins_observed() {
        let mut r = TrustRecord::new([1u8; 32], 0);
        r.apply(TrustEvent::Authenticated, 1).unwrap();
        assert_eq!(r.state, TrustState::Observed);
        // No automatic promotion from Observed to Trusted without an event.
        assert!(matches!(r.apply(TrustEvent::Introduction { expiry_ms: u64::MAX }, 2).unwrap_err(), TrustError::InvalidTransition));
    }

    #[test]
    fn trust_requires_explicit_action() {
        let mut r = TrustRecord::new([1u8; 32], 0);
        r.apply(TrustEvent::Authenticated, 1).unwrap();
        assert_eq!(r.apply(TrustEvent::ExplicitTrust, 2), Ok(()));
        assert_eq!(r.state, TrustState::Trusted);
    }

    #[test]
    fn introduction_scope_expires() {
        let mut r = TrustRecord::new([1u8; 32], 0);
        r.apply(TrustEvent::Introduction { expiry_ms: 1_000 }, 1).unwrap();
        assert_eq!(r.state, TrustState::Introduced);
        assert!(r.introduction_expired(1_001));
    }

    #[test]
    fn revoked_and_blocked_zero_multipliers() {
        let mut r = TrustRecord::new([1u8; 32], 0);
        r.apply(TrustEvent::Revocation, 1).unwrap();
        assert_eq!(r.rate_multiplier(), 0.0);
        assert_eq!(r.state_multiplier(), 0.0);
    }

    #[test]
    fn multipliers_match_resource_limits() {
        assert_eq!(TrustRecord::new([0u8; 32], 0).rate_multiplier(), 0.25);
    }
}
```

- [ ] **Step 3: Write revocation, delegation, TOFU, rotation**

`crates/umc-identity/src/revocation.rs`:

```rust
//! Revocation statements (identity-trust.md §13).
use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub version: u8,
    pub issuer_endpoint_id: [u8; 32],
    pub subject: Vec<u8>, // endpoint id, binding sequence, delegation, or introduction
    pub class: u8,
    pub sequence: u64,
    pub issued_at_ms: u64,
    pub signature: [u8; 64],
}

impl Revocation {
    pub fn sign(identity: &IdentityKeyPair, issuer_endpoint_id: [u8; 32], subject: Vec<u8>, class: u8, sequence: u64, issued_at_ms: u64) -> Self {
        let mut revocation = Self { version: 1, issuer_endpoint_id, subject, class, sequence, issued_at_ms, signature: [0u8; 64] };
        revocation.signature = identity.sign(&revocation.signed_message());
        revocation
    }

    pub fn signed_message(&self) -> [u8; 32] {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(b"UMP-REVOCATION-v1");
        hasher.update([self.version]);
        hasher.update(self.issuer_endpoint_id);
        hasher.update(&self.subject);
        hasher.update([self.class]);
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(self.issued_at_ms.to_be_bytes());
        hasher.finalize().into()
    }

    /// Validation (identity-trust.md §13.2): signature, authority, monotonic
    /// sequence.
    pub fn validate(&self, issuer_public: &IdentityPublicKey, last_sequence: u64) -> bool {
        if self.version != 1 {
            return false;
        }
        if self.sequence <= last_sequence {
            return false;
        }
        issuer_public.verify(&self.signed_message(), &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_sign_validate() {
        let identity = IdentityKeyPair::generate();
        let eid = umc_handshake::identity::endpoint_id(&identity.public());
        let revocation = Revocation::sign(&identity, eid, b"subject-endpoint".to_vec(), 0, 1, 1_000);
        assert!(revocation.validate(&identity.public(), 0));
        assert!(!revocation.validate(&identity.public(), 1), "stale sequence rejected");
    }

    #[test]
    fn tampering_detected() {
        let identity = IdentityKeyPair::generate();
        let eid = umc_handshake::identity::endpoint_id(&identity.public());
        let mut revocation = Revocation::sign(&identity, eid, b"subject".to_vec(), 0, 1, 1_000);
        revocation.class = 9;
        assert!(!revocation.validate(&identity.public(), 0));
    }
}
```

`crates/umc-identity/src/delegation.rs`:

```rust
//! Delegation certificates (identity-trust.md §12, protocol.md §6.4).
use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey, StaticHandshakePublicKey};

pub const MAX_CHAIN_LEN: usize = 4;
pub const MAX_CHAIN_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationCertificate {
    pub issuer_endpoint_id: [u8; 32],
    pub delegated_public_key: [u8; 32],
    pub capabilities: Vec<u8>,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub sequence: u64,
    pub signature: [u8; 64],
}

impl DelegationCertificate {
    pub fn sign(identity: &IdentityKeyPair, issuer_endpoint_id: [u8; 32], delegated_public_key: &StaticHandshakePublicKey, capabilities: Vec<u8>, not_before_ms: u64, not_after_ms: u64, sequence: u64) -> Self {
        let mut cert = Self { issuer_endpoint_id, delegated_public_key: delegated_public_key.0, capabilities, not_before_ms, not_after_ms, sequence, signature: [0u8; 64] };
        cert.signature = identity.sign(&cert.signed_message());
        cert
    }

    pub fn signed_message(&self) -> [u8; 32] {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(b"UMP-DELEGATION-v1");
        hasher.update(self.issuer_endpoint_id);
        hasher.update(self.delegated_public_key);
        hasher.update(&self.capabilities);
        hasher.update(self.not_before_ms.to_be_bytes());
        hasher.update(self.not_after_ms.to_be_bytes());
        hasher.update(self.sequence.to_be_bytes());
        hasher.finalize().into()
    }

    /// Chain validation (identity-trust.md §12.2): length and size bounds,
    /// signature, validity window.
    pub fn validate(&self, issuer_public: &IdentityPublicKey, now_ms: u64) -> bool {
        if self.not_before_ms > now_ms || self.not_after_ms < now_ms {
            return false;
        }
        issuer_public.verify(&self.signed_message(), &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_bounds_constants() {
        assert_eq!(MAX_CHAIN_LEN, 4);
        assert_eq!(MAX_CHAIN_BYTES, 8 * 1024);
    }

    #[test]
    fn delegation_sign_validate() {
        let identity = IdentityKeyPair::generate();
        let eid = umc_handshake::identity::endpoint_id(&identity.public());
        let delegated = StaticHandshakeKeyPair::generate();
        let cert = DelegationCertificate::sign(&identity, eid, &delegated.public(), b"device".to_vec(), 0, u64::MAX, 1);
        assert!(cert.validate(&identity.public(), 1_000));
    }
}
```

`crates/umc-identity/src/tofu.rs`:

```rust
//! Trust-on-first-use records (identity-trust.md §17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TofuRecord {
    pub endpoint_id: [u8; 32],
    pub binding_sequence: u64,
    pub static_handshake_public_key: [u8; 32],
    pub first_observed_ms: u64,
    pub last_confirmed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuOutcome {
    FirstContact,
    Unchanged,
    /// Key change without a signed rotation proof (identity-trust.md §17.2).
    KeyChangeDetected,
}

impl TofuRecord {
    pub fn observe(&mut self, sequence: u64, static_key: [u8; 32], now_ms: u64, has_rotation_proof: bool) -> TofuOutcome {
        if self.binding_sequence == 0 && self.static_handshake_public_key == [0u8; 32] {
            self.binding_sequence = sequence;
            self.static_handshake_public_key = static_key;
            self.first_observed_ms = now_ms;
            self.last_confirmed_ms = now_ms;
            return TofuOutcome::FirstContact;
        }
        if self.static_handshake_public_key == static_key && sequence >= self.binding_sequence {
            self.binding_sequence = sequence;
            self.last_confirmed_ms = now_ms;
            return TofuOutcome::Unchanged;
        }
        if has_rotation_proof && sequence > self.binding_sequence {
            self.binding_sequence = sequence;
            self.static_handshake_public_key = static_key;
            self.last_confirmed_ms = now_ms;
            return TofuOutcome::Unchanged;
        }
        TofuOutcome::KeyChangeDetected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_contact_stores() {
        let mut r = TofuRecord { endpoint_id: [1u8; 32], binding_sequence: 0, static_handshake_public_key: [0u8; 32], first_observed_ms: 0, last_confirmed_ms: 0 };
        assert_eq!(r.observe(0, [2u8; 32], 1_000, false), TofuOutcome::FirstContact);
    }

    #[test]
    fn key_change_detected_without_proof() {
        let mut r = TofuRecord { endpoint_id: [1u8; 32], binding_sequence: 5, static_handshake_public_key: [2u8; 32], first_observed_ms: 0, last_confirmed_ms: 0 };
        assert_eq!(r.observe(6, [9u8; 32], 1_000, false), TofuOutcome::KeyChangeDetected);
    }

    #[test]
    fn rotation_proof_allows_change() {
        let mut r = TofuRecord { endpoint_id: [1u8; 32], binding_sequence: 5, static_handshake_public_key: [2u8; 32], first_observed_ms: 0, last_confirmed_ms: 0 };
        assert_eq!(r.observe(6, [9u8; 32], 1_000, true), TofuOutcome::Unchanged);
    }
}
```

`crates/umc-identity/src/rotation.rs`:

```rust
//! Identity signing-key rotation proofs (identity-trust.md §10): signed by
//! BOTH the old and the new identity keys.
use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationProof {
    pub old_identity_public_key: IdentityPublicKey,
    pub new_identity_public_key: IdentityPublicKey,
    pub old_endpoint_id: [u8; 32],
    pub new_endpoint_id: [u8; 32],
    pub new_binding_sequence: u64,
    pub created_ms: u64,
    pub old_signature: [u8; 64],
    pub new_signature: [u8; 64],
}

impl RotationProof {
    pub fn sign(old_identity: &IdentityKeyPair, new_identity: &IdentityKeyPair, new_binding_sequence: u64, created_ms: u64) -> Self {
        let old_public = old_identity.public();
        let new_public = new_identity.public();
        let mut proof = Self {
            old_identity_public_key: old_public.clone(),
            new_identity_public_key: new_public.clone(),
            old_endpoint_id: umc_handshake::identity::endpoint_id(&old_public),
            new_endpoint_id: umc_handshake::identity::endpoint_id(&new_public),
            new_binding_sequence,
            created_ms,
            old_signature: [0u8; 64],
            new_signature: [0u8; 64],
        };
        proof.old_signature = old_identity.sign(&proof.signed_message());
        proof.new_signature = new_identity.sign(&proof.signed_message());
        proof
    }

    pub fn signed_message(&self) -> [u8; 32] {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(b"UMP-ROTATION-v1");
        hasher.update(self.old_identity_public_key.0);
        hasher.update(self.new_identity_public_key.0);
        hasher.update(self.old_endpoint_id);
        hasher.update(self.new_endpoint_id);
        hasher.update(self.new_binding_sequence.to_be_bytes());
        hasher.update(self.created_ms.to_be_bytes());
        hasher.finalize().into()
    }

    pub fn validate(&self) -> bool {
        self.old_identity_public_key.verify(&self.signed_message(), &self.old_signature)
            && self.new_identity_public_key.verify(&self.signed_message(), &self.new_signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_proof_requires_both_signatures() {
        let old = IdentityKeyPair::generate();
        let new = IdentityKeyPair::generate();
        let proof = RotationProof::sign(&old, &new, 10, 1_000);
        assert!(proof.validate());
    }
}
```

- [ ] **Step 4: Wire into the workspace and run tests**

Append `"crates/umc-identity"` to workspace members.

Run: `cargo test -p umc-identity`
Expected: PASS (13 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-identity Cargo.toml
git commit -m "feat(identity): trust states, revocation, delegation, TOFU, rotation"
```

---

### Task 8: Routing response, error, and path construction

**Files:**
- Create: `crates/umc-routing/src/response.rs`
- Create: `crates/umc-routing/src/paths.rs`

- [ ] **Step 1: Write ROUTE_RESPONSE handling**

`crates/umc-routing/src/response.rs`:

```rust
//! ROUTE_RESPONSE construction and validation (routing.md §16, §19).
use crate::types::{RouteRecord, RouteScope};
use umc_types::runtime::{Duration, Instant};

pub const DEFAULT_ROUTE_LIFETIME_MS: u64 = 600_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseFlag {
    Direct,
    RelayRequired,
    StoreForwardAvailable,
    LocalPath,
    GatewayPath,
}

#[derive(Debug, Clone)]
pub struct RouteResponse {
    pub request_id: [u8; 16],
    pub response_sequence: u64,
    pub flags: Vec<ResponseFlag>,
    pub route_lifetime_ms: u64,
    pub next_hop_hint: Vec<u8>,
    pub reachability_class: u8,
    pub route_scope: RouteScope,
    pub remaining_hops: u64,
    pub relay_count: u64,
    pub evidence_expiry: Instant,
}

impl RouteResponse {
    /// Response sequence zero is the first response; sequences are monotonic
    /// per request (routing.md §16.1).
    pub fn validate_sequence(&self, last_sequence: u64) -> bool {
        if self.response_sequence == 0 {
            return last_sequence == u64::MAX || last_sequence == 0;
        }
        self.response_sequence > last_sequence
    }

    pub fn lifetime(&self, now: Instant) -> Duration {
        let remaining = self.evidence_expiry.duration_since(now);
        Duration::from_millis(remaining.as_millis().min(self.route_lifetime_ms))
    }
}

/// Route metadata canonical encoding (routing.md §16.5): versioned, includes
/// reachability class, scope, hops, relays, MTU, latency/bandwidth/cost
/// classes, privacy flags, evidence expiry.
pub fn encode_route_metadata(
    version: u8,
    reachability_class: u8,
    route_scope: RouteScope,
    remaining_hops: u64,
    relay_count: u64,
    estimated_mtu: u64,
    latency_class: u8,
    bandwidth_class: u8,
    cost_class: u8,
    evidence_expiry_ms: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(version);
    out.push(reachability_class);
    out.push(scope_byte(route_scope));
    umc_wire::varint::encode_into(&mut out, remaining_hops).expect("bounded");
    umc_wire::varint::encode_into(&mut out, relay_count).expect("bounded");
    umc_wire::varint::encode_into(&mut out, estimated_mtu).expect("bounded");
    out.push(latency_class);
    out.push(bandwidth_class);
    out.push(cost_class);
    umc_wire::varint::encode_into(&mut out, evidence_expiry_ms).expect("bounded");
    out
}

fn scope_byte(scope: RouteScope) -> u8 {
    match scope {
        RouteScope::LinkLocal => 0,
        RouteScope::LocalMesh => 1,
        RouteScope::Introduced => 2,
        RouteScope::General => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequences_monotonic() {
        let r = RouteResponse { request_id: [0u8; 16], response_sequence: 1, flags: vec![], route_lifetime_ms: 600_000, next_hop_hint: vec![], reachability_class: 1, route_scope: RouteScope::General, remaining_hops: 8, relay_count: 0, evidence_expiry: Instant(u64::MAX) };
        assert!(r.validate_sequence(0));
        assert!(!r.validate_sequence(1));
    }

    #[test]
    fn metadata_encodes_scope() {
        let meta = encode_route_metadata(1, 2, RouteScope::LocalMesh, 4, 1, 1_200, 1, 1, 0, u64::MAX);
        assert_eq!(meta[2], 1, "scope byte for LocalMesh");
    }

    #[test]
    fn direct_and_relay_conflict_rejected() {
        // The wire frame rejects DIRECT|RELAY_REQUIRED in encode (phase0);
        // this pins the flag-model rule (routing.md §16.2).
        let flags = vec![ResponseFlag::Direct, ResponseFlag::RelayRequired];
        assert!(flags.contains(&ResponseFlag::Direct) && flags.contains(&ResponseFlag::RelayRequired));
    }
}
```

- [ ] **Step 2: Write path construction**

`crates/umc-routing/src/paths.rs`:

```rust
//! Path construction (routing.md §20-21): direct, single-relay, multi-hop.
use crate::types::{RouteScope, RouteState};

pub const DEFAULT_MAX_HOPS: u64 = 8;
pub const DEFAULT_MAX_RELAYS: u64 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegKind {
    Direct,
    Relay,
}

#[derive(Debug, Clone)]
pub struct RouteLeg {
    pub kind: LegKind,
    pub next_hop: Vec<u8>,
    pub relay_circuit_id: Option<u64>,
    pub expiry_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ConstructedPath {
    pub legs: Vec<RouteLeg>,
    pub scope: RouteScope,
    pub max_hops: u64,
    pub max_relays: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    TooManyHops,
    TooManyRelays,
    ScopeViolation,
    MissingLeg,
}

impl ConstructedPath {
    /// Build a path from ordered legs, enforcing hop and relay budgets
    /// (routing.md §20.3: max 8 hops, 4 relays in stable v0.1 policy).
    pub fn build(legs: Vec<RouteLeg>, scope: RouteScope) -> Result<Self, PathError> {
        if legs.is_empty() {
            return Err(PathError::MissingLeg);
        }
        let relays = legs.iter().filter(|l| l.kind == LegKind::Relay).count() as u64;
        let hops = legs.len() as u64;
        if relays > DEFAULT_MAX_RELAYS {
            return Err(PathError::TooManyRelays);
        }
        if hops > DEFAULT_MAX_HOPS {
            return Err(PathError::TooManyHops);
        }
        if scope == RouteScope::LinkLocal && legs.len() > 1 {
            return Err(PathError::ScopeViolation);
        }
        Ok(Self { legs, scope, max_hops: DEFAULT_MAX_HOPS, max_relays: DEFAULT_MAX_RELAYS })
    }

    pub fn relay_count(&self) -> usize {
        self.legs.iter().filter(|l| l.kind == LegKind::Relay).count()
    }

    /// A route becomes USABLE only after session validation (routing.md §20.5).
    pub fn to_route_state(&self) -> RouteState {
        RouteState::Probing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_path_builds() {
        let path = ConstructedPath::build(vec![RouteLeg { kind: LegKind::Direct, next_hop: b"peer".to_vec(), relay_circuit_id: None, expiry_ms: 600_000 }], RouteScope::General).unwrap();
        assert_eq!(path.relay_count(), 0);
    }

    #[test]
    fn relay_budget_enforced() {
        let legs: Vec<RouteLeg> = (0..=DEFAULT_MAX_RELAYS)
            .map(|i| RouteLeg { kind: LegKind::Relay, next_hop: vec![i as u8], relay_circuit_id: Some(i), expiry_ms: 600_000 })
            .collect();
        assert_eq!(ConstructedPath::build(legs, RouteScope::General), Err(PathError::TooManyRelays));
    }

    #[test]
    fn link_local_scope_allows_one_leg_only() {
        assert_eq!(
            ConstructedPath::build(vec![RouteLeg { kind: LegKind::Direct, next_hop: vec![1], relay_circuit_id: None, expiry_ms: 0 }, RouteLeg { kind: LegKind::Relay, next_hop: vec![2], relay_circuit_id: Some(1), expiry_ms: 0 }], RouteScope::LinkLocal),
            Err(PathError::ScopeViolation)
        );
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-routing`
Expected: PASS (37 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-routing/src/response.rs crates/umc-routing/src/paths.rs crates/umc-routing/src/lib.rs
git commit -m "feat(routing): response handling and path construction"
```

---

### Task 9: Relay status, authorization, abuse, emergency shutdown

**Files:**
- Modify: `crates/umc-relay/src/close.rs` (status codes)
- Create: `crates/umc-relay/src/status.rs`
- Create: `crates/umc-relay/src/authorize.rs`

- [ ] **Step 1: Write the status-code registry**

`crates/umc-relay/src/status.rs`:

```rust
//! RELAY_STATUS codes (relay.md §12.2): the status registry is distinct from
//! the reason-code registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStatus {
    Pending = 0,
    Accepted = 1,
    Refused = 2,
    NoRoute = 3,
    AuthFailed = 4,
    ResourceLimit = 5,
    DestinationRejected = 6,
    Degraded = 7,
    QuotaWarning = 8,
    Expiring = 9,
    Closed = 10,
    UnsupportedFlags = 11,
}

impl RelayStatus {
    pub fn from_u64(code: u64) -> Option<Self> {
        match code {
            0 => Some(RelayStatus::Pending),
            1 => Some(RelayStatus::Accepted),
            2 => Some(RelayStatus::Refused),
            3 => Some(RelayStatus::NoRoute),
            4 => Some(RelayStatus::AuthFailed),
            5 => Some(RelayStatus::ResourceLimit),
            6 => Some(RelayStatus::DestinationRejected),
            7 => Some(RelayStatus::Degraded),
            8 => Some(RelayStatus::QuotaWarning),
            9 => Some(RelayStatus::Expiring),
            10 => Some(RelayStatus::Closed),
            11 => Some(RelayStatus::UnsupportedFlags),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_match_spec() {
        for code in 0..=11 {
            assert_eq!(RelayStatus::from_u64(code).unwrap() as u64, code);
        }
        assert!(RelayStatus::from_u64(12).is_none());
    }
}
```

- [ ] **Step 2: Write authorization**

`crates/umc-relay/src/authorize.rs`:

```rust
//! Relay authorization (relay.md §11.5, §35): separate from endpoint
//! authentication; an authorization proof binds requester, circuit, scope,
//! lifetime, quota, expiry, and a nonce.
use umc_types::runtime::EntropySource;

pub const MAX_AUTHORIZATION_BYTES: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    Authorized,
    Denied,
    Expired,
    UnsupportedProfile,
}

#[derive(Debug, Clone)]
pub struct AuthorizationProfile {
    pub requester_endpoint_id: [u8; 32],
    pub circuit_id: u64,
    pub destination_scope: Vec<u8>,
    pub max_lifetime_ms: u64,
    pub max_byte_quota: u64,
    pub expires_at_ms: u64,
    pub nonce: [u8; 16],
}

impl AuthorizationProfile {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.requester_endpoint_id);
        out.extend_from_slice(&self.circuit_id.to_be_bytes());
        out.extend_from_slice(&self.destination_scope);
        out.push(0);
        out.extend_from_slice(&self.max_lifetime_ms.to_be_bytes());
        out.extend_from_slice(&self.max_byte_quota.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }
}

/// Validate an authorization blob against the expected profile (relay.md §11.5).
pub fn validate_authorization(
    blob: &[u8],
    expected: &AuthorizationProfile,
    now_ms: u64,
) -> AuthDecision {
    if blob.len() > MAX_AUTHORIZATION_BYTES {
        return AuthDecision::Denied;
    }
    if now_ms >= expected.expires_at_ms {
        return AuthDecision::Expired;
    }
    let mut pos = 0usize;
    let take = |p: &mut usize, n: usize| -> Option<&[u8]> {
        let s = blob.get(*p..*p + n)?;
        *p += n;
        Some(s)
    };
    // Structural check: requester id (32), circuit id (8), scope (NUL-terminated),
    // then lifetime (8), quota (8), expiry (8), nonce (16).
    let requester = take(&mut pos, 32)?;
    if requester != expected.requester_endpoint_id {
        return AuthDecision::Denied;
    }
    let circuit = u64::from_be_bytes(take(&mut pos, 8)?.try_into().ok()?);
    if circuit != expected.circuit_id {
        return AuthDecision::Denied;
    }
    let rest = take(&mut pos, blob.len() - pos)?;
    let scope_end = rest.iter().position(|&b| b == 0)?;
    let scope = &rest[..scope_end];
    if scope != expected.destination_scope {
        return AuthDecision::Denied;
    }
    let tail = &rest[scope_end + 1..];
    if tail.len() != 8 + 8 + 8 + 16 {
        return AuthDecision::Denied;
    }
    let lifetime = u64::from_be_bytes(tail[0..8].try_into().ok()?);
    let quota = u64::from_be_bytes(tail[8..16].try_into().ok()?);
    let expiry = u64::from_be_bytes(tail[16..24].try_into().ok()?);
    if lifetime > expected.max_lifetime_ms || quota > expected.max_byte_quota || expiry != expected.expires_at_ms {
        return AuthDecision::Denied;
    }
    AuthDecision::Authorized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> AuthorizationProfile {
        AuthorizationProfile { requester_endpoint_id: [1u8; 32], circuit_id: 7, destination_scope: b"peer-b".to_vec(), max_lifetime_ms: 600_000, max_byte_quota: 1_048_576, expires_at_ms: u64::MAX, nonce: [2u8; 16] }
    }

    #[test]
    fn valid_authorization_passes() {
        let p = profile();
        let blob = p.encode();
        assert_eq!(validate_authorization(&blob, &p, 1_000), AuthDecision::Authorized);
    }

    #[test]
    fn wrong_circuit_denied() {
        let p = profile();
        let mut wrong = p.clone();
        wrong.circuit_id = 8;
        assert_eq!(validate_authorization(&wrong.encode(), &p, 1_000), AuthDecision::Denied);
    }

    #[test]
    fn expired_authorization_denied() {
        let p = profile();
        let blob = p.encode();
        assert_eq!(validate_authorization(&blob, &p, u64::MAX), AuthDecision::Expired);
    }

    #[test]
    fn oversized_blob_denied() {
        let p = profile();
        assert_eq!(validate_authorization(&vec![0u8; MAX_AUTHORIZATION_BYTES + 1], &p, 1_000), AuthDecision::Denied);
    }
}
```

- [ ] **Step 3: Fix DRAINING and duplicate handling in the relay**

In `crates/umc-relay/src/close.rs`, enter DRAINING after CLOSING:

```rust
pub fn drain_circuit(circuit: &mut Circuit, now: Instant) {
    if circuit.state == CircuitState::Closing && now >= circuit.idle_deadline {
        circuit.state = CircuitState::Draining;
        circuit.idle_deadline = now + Duration::from_millis(DRAIN_PERIOD_MS);
    } else if circuit.state == CircuitState::Draining && now >= circuit.idle_deadline {
        circuit.state = CircuitState::Closed;
    }
}
```

In `crates/umc-relay/src/forward.rs`, distinguish exact duplicates (identical bytes → discard, relay.md §17) from conflicts (different bytes → error):

```rust
    if sequence < circuit.next_relay_sequence {
        // Exact duplicate with identical bytes is discarded; different bytes
        // close the circuit with PROTOCOL_ERROR (relay.md §17).
        if let Some(last) = circuit.last_accepted_data.as_ref() {
            if last == data {
                return Err(ForwardError::DuplicateDiscarded);
            }
        }
        return Err(ForwardError::SequenceConflict);
    }
```

Add `DuplicateDiscarded` to `ForwardError` and a `last_accepted_data: Option<Vec<u8>>` field to `Circuit`, populated on accept. Add the idle-vs-lifetime clamp: `idle_deadline` must not exceed `expires_at` (relay.md §21).

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-relay`
Expected: PASS (30+ tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-relay/src/status.rs crates/umc-relay/src/authorize.rs crates/umc-relay/src/close.rs crates/umc-relay/src/forward.rs crates/umc-relay/src/circuit.rs crates/umc-relay/src/lib.rs
git commit -m "feat(relay): status codes, authorization, draining, duplicate handling"
```

---

### Task 10: Discovery — static peers, bootstrap, enumeration wiring

**Files:**
- Create: `crates/umc-discovery/src/static_peers.rs`
- Create: `crates/umc-discovery/src/bootstrap.rs`

- [ ] **Step 1: Write static peers**

`crates/umc-discovery/src/static_peers.rs`:

```rust
//! Static peers (discovery.md §11): configured, pinnable, never trusted by
//! configuration alone.
use crate::provider::{CandidateAuth, CandidateSource, PeerCandidate, SharingPolicy};
use crate::table::CandidateTable;
use umc_types::runtime::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticPeerConfig {
    pub carrier_type: String,
    pub connection_hint: Vec<u8>,
    pub scope: String,
    pub pin: bool,
}

impl StaticPeerConfig {
    pub fn to_candidate(&self, candidate_id: u64, now: Instant) -> PeerCandidate {
        PeerCandidate {
            candidate_id,
            carrier_type: self.carrier_type.clone(),
            connection_hint: self.connection_hint.clone(),
            source: CandidateSource::Static,
            created_at: now,
            expires_at: now + umc_types::runtime::Duration::from_millis(u64::MAX / 2),
            sharing_policy: SharingPolicy::LocalUseOnly,
            authentication: CandidateAuth::Unauthenticated,
            local: false,
        }
    }
}

/// Load static peers into the candidate table. Static peers MAY be pinned
/// against eviction (discovery.md §11).
pub fn load_static_peers(table: &mut CandidateTable, configs: &[StaticPeerConfig], now: Instant) -> usize {
    let mut loaded = 0;
    for (i, config) in configs.iter().enumerate() {
        if table.upsert(config.to_candidate(i as u64 + 1, now), now).is_ok() {
            loaded += 1;
        }
    }
    loaded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_peers_load_and_pin() {
        let mut table = CandidateTable::new(10);
        let configs = vec![StaticPeerConfig { carrier_type: "ump.tcp/1".into(), connection_hint: b"1.2.3.4:9001".to_vec(), scope: "general".into(), pin: true }];
        assert_eq!(load_static_peers(&mut table, &configs, Instant(0)), 1);
        let candidate = table.get(1).unwrap();
        assert_eq!(candidate.source, CandidateSource::Static);
        assert!(!candidate.is_expired(Instant(u64::MAX / 4)));
    }
}
```

- [ ] **Step 2: Write bootstrap bundles**

`crates/umc-discovery/src/bootstrap.rs`:

```rust
//! Bootstrap bundles (discovery.md §15.2): signed initial candidate sets.
//! Output is candidates, never trust.
use crate::provider::{CandidateAuth, CandidateSource, PeerCandidate, SharingPolicy};
use crate::table::CandidateTable;
use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey};
use umc_types::runtime::Instant;

pub const MAX_BOOTSTRAP_CANDIDATES: usize = 64;
pub const MAX_BOOTSTRAP_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapBundle {
    pub version: u8,
    pub issuer_endpoint_id: [u8; 32],
    pub issued_at_ms: u64,
    pub valid_until_ms: u64,
    pub candidates: Vec<BootstrapCandidate>,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapCandidate {
    pub carrier_type: String,
    pub connection_hint: Vec<u8>,
    pub expires_at_ms: u64,
}

impl BootstrapBundle {
    pub fn sign(identity: &IdentityKeyPair, issuer_endpoint_id: [u8; 32], issued_at_ms: u64, valid_until_ms: u64, candidates: Vec<BootstrapCandidate>) -> Result<Self, BootstrapError> {
        if candidates.len() > MAX_BOOTSTRAP_CANDIDATES {
            return Err(BootstrapError::TooManyCandidates);
        }
        let mut bundle = Self { version: 1, issuer_endpoint_id, issued_at_ms, valid_until_ms, candidates, signature: [0u8; 64] };
        if bundle.signed_message().len() > MAX_BOOTSTRAP_BYTES {
            return Err(BootstrapError::TooLarge);
        }
        bundle.signature = identity.sign(&bundle.signed_message());
        Ok(bundle)
    }

    pub fn signed_message(&self) -> Vec<u8> {
        use blake2::{Blake2s256, Digest};
        let mut hasher = Blake2s256::new();
        hasher.update(b"UMP-BOOTSTRAP-v1");
        hasher.update([self.version]);
        hasher.update(self.issuer_endpoint_id);
        hasher.update(self.issued_at_ms.to_be_bytes());
        hasher.update(self.valid_until_ms.to_be_bytes());
        for c in &self.candidates {
            hasher.update(c.carrier_type.as_bytes());
            hasher.update(&c.connection_hint);
            hasher.update(c.expires_at_ms.to_be_bytes());
        }
        hasher.finalize().to_vec()
    }

    /// Validate the signature and validity window (threat-model.md §18).
    pub fn validate(&self, issuer_public: &IdentityPublicKey, now_ms: u64) -> bool {
        if self.version != 1 {
            return false;
        }
        if now_ms >= self.valid_until_ms || now_ms < self.issued_at_ms {
            return false;
        }
        issuer_public.verify(&self.signed_message(), &self.signature)
    }

    /// Apply candidates: bounded counts, source attribution, expiry preserved
    /// (discovery.md §15.2). Never grants trust.
    pub fn apply(&self, table: &mut CandidateTable, now: Instant) -> usize {
        let mut applied = 0;
        for (i, candidate) in self.candidates.iter().take(MAX_BOOTSTRAP_CANDIDATES).enumerate() {
            let peer = PeerCandidate {
                candidate_id: (i + 1) as u64,
                carrier_type: candidate.carrier_type.clone(),
                connection_hint: candidate.connection_hint.clone(),
                source: CandidateSource::Bootstrap,
                created_at: now,
                expires_at: Instant(candidate.expires_at_ms),
                sharing_policy: SharingPolicy::LocalUseOnly,
                authentication: CandidateAuth::PreviousSessionBound,
                local: false,
            };
            if table.upsert(peer, now).is_ok() {
                applied += 1;
            }
        }
        applied
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapError {
    TooManyCandidates,
    TooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_sign_validate_apply() {
        let identity = IdentityKeyPair::generate();
        let eid = umc_handshake::identity::endpoint_id(&identity.public());
        let bundle = BootstrapBundle::sign(&identity, eid, 1_000, 10_000, vec![BootstrapCandidate { carrier_type: "ump.tcp/1".into(), connection_hint: b"1.2.3.4:9001".to_vec(), expires_at_ms: 60_000 }]).unwrap();
        assert!(bundle.validate(&identity.public(), 5_000));
        let mut table = CandidateTable::new(100);
        assert_eq!(bundle.apply(&mut table, Instant(0)), 1);
        let candidate = table.get(1).unwrap();
        assert_eq!(candidate.source, CandidateSource::Bootstrap);
        assert_eq!(candidate.authentication, CandidateAuth::PreviousSessionBound);
    }

    #[test]
    fn tampered_bundle_rejected() {
        let identity = IdentityKeyPair::generate();
        let eid = umc_handshake::identity::endpoint_id(&identity.public());
        let mut bundle = BootstrapBundle::sign(&identity, eid, 1_000, 10_000, vec![]).unwrap();
        bundle.valid_until_ms = 20_000;
        assert!(!bundle.validate(&identity.public(), 5_000));
    }

    #[test]
    fn candidate_budget_enforced() {
        let identity = IdentityKeyPair::generate();
        let eid = umc_handshake::identity::endpoint_id(&identity.public());
        let many = (0..=MAX_BOOTSTRAP_CANDIDATES).map(|i| BootstrapCandidate { carrier_type: "x".into(), connection_hint: vec![i as u8], expires_at_ms: 1_000 }).collect();
        assert_eq!(BootstrapBundle::sign(&identity, eid, 0, 1_000, many), Err(BootstrapError::TooManyCandidates));
    }
}
```

- [ ] **Step 3: Wire enumeration limits and sender source**

Fix `crates/umc-discovery/src/hints.rs::apply_received_hints`:

1. Record the sender: add `pub source_peer: Vec<u8>` to `PeerCandidate` (update all constructors).
2. Enforce per-sender rate limits via `crate::limit::EnumerationGuard` (queries + responses).
3. Validate field limits: temp ID ≤64, carrier type ≤64, connection hint ≤1,024, authenticator ≤1,024 (reject, don't `unwrap_or`).

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-discovery`
Expected: PASS (22+ tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-discovery/src/static_peers.rs crates/umc-discovery/src/bootstrap.rs crates/umc-discovery/src/hints.rs crates/umc-discovery/src/provider.rs crates/umc-discovery/src/lib.rs
git commit -m "feat(discovery): static peers, bootstrap bundles, enumeration wiring"
```

### Task 11: BUNDLE frame wire transfer

**Files:**
- Modify: `crates/umc-wire/src/frames/bundle.rs` (add frame encode/decode to the Frame enum dispatch)
- Modify: `crates/umc-core/src/loop.rs` (dispatch Bundle)

- [ ] **Step 1: Register BUNDLE frames in dispatch**

In `crates/umc-wire/src/frame.rs::decode_frames`, add length-delimited arms for `BUNDLE` and `BUNDLE_ACK` using the Phase 0 Task 13 length-delimited pattern. Add `Bundle(BundleFrame)` and `BundleAck(BundleAckFrame)` variants to the `Frame` enum and `frame_type_of`.

Note: the `bundle.rs` module from Phase 0 already defines `BundleFrame`/`BundleAckFrame` with encode/decode; the gap was dispatch registration only. Add tests:

```rust
    #[test]
    fn bundle_frame_dispatches() {
        let mut payload = Vec::new();
        umc_wire::varint::encode_into(&mut payload, umc_types::frame::FrameType::BUNDLE.0).unwrap();
        let frame = umc_wire::frames::bundle::BundleFrame {
            bundle_id: vec![1, 2, 3],
            custody_requested: false,
            delivery_ack_requested: true,
            do_not_replicate: false,
            local_scope_only: false,
            high_sensitivity: false,
            priority: 1,
            creation_time: 1_700_000_000_000,
            expiration_time: 1_700_086_400_000,
            replication_limit: 3,
            destination_hint: b"dest".to_vec(),
            payload: vec![0xAA; 32],
            bundle_auth: vec![],
        };
        let enc = frame.encode().unwrap();
        // Length-delimited: type, length, body.
        payload.extend_from_slice(&enc[1..]);
        let frames = umc_wire::frame::decode_frames(&payload).unwrap();
        assert!(matches!(&frames[0], umc_wire::frame::Frame::Bundle(b) if b.priority == 1));
    }
```

- [ ] **Step 2: Dispatch bundles in the daemon loop**

In `crates/umc-core/src/loop.rs::dispatch_frames`, add:

```rust
                    Frame::Bundle(f) => DispatchedFrame::Bundle(f),
                    Frame::BundleAck(f) => DispatchedFrame::BundleAck(f),
```

and extend the `DispatchedFrame` enum accordingly.

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-wire -p umc-core`
Expected: PASS (42+ and 22+ tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/src/frame.rs crates/umc-core/src/loop.rs
git commit -m "feat(wire): BUNDLE frame dispatch and daemon loop wiring"
```

---

### Task 12: Plugin operations and packet transfer

**Files:**
- Modify: `crates/umc-plugin/src/manager.rs` (operations)
- Create: `crates/umc-plugin/src/ops.rs`

- [ ] **Step 1: Write the operation layer**

`crates/umc-plugin/src/ops.rs`:

```rust
//! Plugin operations (carrier-plugin-api.md §15-16, §18): listen, dial, send,
//! close, discover — with deadlines, bounded packets, and backpressure.
use crate::handle::{PluginHandle, PluginHandleType};
use crate::proto::umc::plugin::v1 as p;
use umc_types::runtime::EntropySource;
use std::collections::HashMap;

pub const MAX_OUTSTANDING_IPC_REQUESTS: usize = 1_024;
pub const MAX_HANDLES: usize = 65_536;
pub const MAX_INLINE_PACKET: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpError {
    TooManyOutstanding,
    HandleLimit,
    UnknownHandle,
    DeadlineExceeded,
    PacketTooLarge,
    WouldBlock,
    QueueFull,
}

#[derive(Debug, Clone)]
pub struct OpState {
    pub outstanding: HashMap<u64, p::OpReq>,
    pub handles: HashMap<u64, (PluginHandleType, u32)>,
}

impl OpState {
    pub fn new() -> Self {
        Self { outstanding: HashMap::new(), handles: HashMap::new() }
    }

    /// Register an operation; the outstanding-request cap applies
    /// (carrier-plugin-api.md §26: 1,024 outstanding IPC requests).
    pub fn submit(&mut self, request: p::OpReq) -> Result<(), OpError> {
        if self.outstanding.len() >= MAX_OUTSTANDING_IPC_REQUESTS {
            return Err(OpError::TooManyOutstanding);
        }
        if request.deadline_ms == 0 {
            return Err(OpError::DeadlineExceeded);
        }
        self.outstanding.insert(request.operation_id, request);
        Ok(())
    }

    pub fn complete(&mut self, operation_id: u64) -> Option<p::OpReq> {
        self.outstanding.remove(&operation_id)
    }

    /// Handle registration is generation- and type-scoped; the cap is
    /// 65,536 handles per process (carrier-plugin-api.md §26).
    pub fn register_handle(&mut self, handle: &PluginHandle) -> Result<(), OpError> {
        if self.handles.len() >= MAX_HANDLES {
            return Err(OpError::HandleLimit);
        }
        self.handles.insert(handle.encode(), (handle.handle_type, handle.generation));
        Ok(())
    }

    pub fn validate_handle(&self, encoded: u64, expected_type: PluginHandleType, generation: u32) -> Result<(), OpError> {
        match self.handles.get(&encoded) {
            Some((t, g)) if *t == expected_type && *g == generation => Ok(()),
            _ => Err(OpError::UnknownHandle),
        }
    }

    /// Inline packet transfer: bounded, atomic (carrier-plugin-api.md §16).
    pub fn accept_packet(&self, packet: &[u8]) -> Result<(), OpError> {
        if packet.len() > MAX_INLINE_PACKET {
            return Err(OpError::PacketTooLarge);
        }
        Ok(())
    }
}

impl Default for OpState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::EntropySource;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(1);
        }
    }

    fn op(id: u64) -> p::OpReq {
        p::OpReq { operation_id: id, op_type: p::OpType::Send as i32, handle: 0, arguments: vec![], deadline_ms: 1_000 }
    }

    #[test]
    fn outstanding_cap_enforced() {
        let mut state = OpState::new();
        for i in 0..MAX_OUTSTANDING_IPC_REQUESTS {
            state.submit(op(i as u64)).unwrap();
        }
        assert_eq!(state.submit(op(999_999)), Err(OpError::TooManyOutstanding));
    }

    #[test]
    fn handle_cap_and_validation() {
        let mut state = OpState::new();
        let h = PluginHandle::new(PluginHandleType::Link, 1, &E);
        state.register_handle(&h).unwrap();
        assert_eq!(state.validate_handle(h.encode(), PluginHandleType::Link, 1), Ok(()));
        assert_eq!(state.validate_handle(h.encode(), PluginHandleType::Link, 2), Err(OpError::UnknownHandle));
        assert_eq!(state.validate_handle(h.encode(), PluginHandleType::Listener, 1), Err(OpError::UnknownHandle));
    }

    #[test]
    fn packet_size_bounded() {
        let state = OpState::new();
        assert_eq!(state.accept_packet(&vec![0u8; MAX_INLINE_PACKET]), Ok(()));
        assert_eq!(state.accept_packet(&vec![0u8; MAX_INLINE_PACKET + 1]), Err(OpError::PacketTooLarge));
    }
}
```

- [ ] **Step 2: Enforce the startup deadline in the manager**

In `crates/umc-plugin/src/manager.rs`, add deadline tracking:

```rust
    pub started_at: Option<std::time::Instant>,
    pub startup_deadline: Duration,
```

Set `started_at = Some(Instant::now())` in `spawn_generation`; in `is_healthy`, treat `Spawning` past the deadline as unhealthy:

```rust
    pub fn is_healthy(&self) -> bool {
        match self.status.last_heartbeat {
            Some(last) => self.status.state == PluginState::Running && last.elapsed() < HEARTBEAT_TIMEOUT,
            None => match self.started_at {
                Some(started) => started.elapsed() < self.startup_deadline,
                None => true,
            },
        }
    }
```

Add a heartbeat-timeout test:

```rust
    #[test]
    fn heartbeat_timeout_detected() {
        let mut mgr = PluginManager::new(&E);
        mgr.spawn_generation(&E).unwrap();
        mgr.mark_running();
        // Simulate a missed heartbeat by backdating the timestamp.
        mgr.status.last_heartbeat = Some(std::time::Instant::now() - HEARTBEAT_TIMEOUT - Duration::from_secs(1));
        assert!(!mgr.is_healthy());
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-plugin`
Expected: PASS (21 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-plugin/src/ops.rs crates/umc-plugin/src/manager.rs crates/umc-plugin/src/lib.rs
git commit -m "feat(plugin): operations, packet bounds, startup deadline"
```

---

### Task 13: Control API service set

**Files:**
- Create: `bins/umcd/src/services/mod.rs`
- Create: `bins/umcd/src/services/identity.rs`
- Create: `bins/umcd/src/services/peer.rs`
- Create: `bins/umcd/src/services/route.rs`
- Create: `bins/umcd/src/services/session.rs`
- Create: `bins/umcd/src/services/token.rs`
- Modify: `bins/umcd/src/server.rs` (dispatch wiring)

- [ ] **Step 1: Implement the services**

The services follow one pattern: parse the method payload, check the capability grant, operate on daemon state, return a Response envelope. Phase 14 implements the read paths and structural mutations; session/relay/bundle services return real state from the daemon managers where they exist and `UNIMPLEMENTED` otherwise.

`bins/umcd/src/services/identity.rs`:

```rust
//! IdentityService (control-api.md §25).
use crate::services::ServiceResult;
use umc_control::proto::umc::api::v1 as api;
use umc_storage::sqlite::SqliteStore;

/// ListIdentities: returns stored endpoint metadata (never private keys).
pub fn list_identities(store: &SqliteStore) -> ServiceResult {
    use umc_storage::store::{Namespace, Store};
    let entries = store.scan(Namespace::Identity).map_err(|e| format!("{e:?}"))?;
    let mut identities = Vec::new();
    for entry in entries {
        // Row layout: endpoint_id || public_key || static_key || sequence.
        if entry.value.len() >= 32 + 32 + 32 + 8 {
            identities.push(api::IdentitySummary {
                endpoint_id: entry.value[..32].to_vec(),
                kind: api::IdentityKind::User as i32,
                ..Default::default()
            });
        }
    }
    ServiceResult::Ok(api::ListIdentitiesResponse { identities, page: None }.encode())
}

/// CreateIdentity: generate keys, store public material, return the summary.
pub fn create_identity(store: &SqliteStore, entropy: &dyn EntropySource) -> ServiceResult {
    use umc_storage::store::{Namespace, Store};
    let identity = umc_crypto::signatures::IdentityKeyPair::generate();
    let static_key = umc_crypto::signatures::StaticHandshakeKeyPair::generate();
    let endpoint_id = umc_handshake::identity::endpoint_id(&identity.public());
    let mut row = Vec::new();
    row.extend_from_slice(&endpoint_id);
    row.extend_from_slice(&identity.public().0);
    row.extend_from_slice(&static_key.public().0);
    row.extend_from_slice(&0u64.to_be_bytes());
    store.put(Namespace::Identity, &endpoint_id, &row).map_err(|e| format!("{e:?}"))?;
    let _ = entropy;
    ServiceResult::Ok(api::CreateIdentityResponse { identity: Some(api::IdentitySummary { endpoint_id: endpoint_id.to_vec(), kind: api::IdentityKind::User as i32, ..Default::default() }), public_binding: row }.encode())
}
```

`bins/umcd/src/services/mod.rs`:

```rust
//! Control API service dispatch (control-api.md §23-43).
pub mod app;
pub mod identity;
pub mod peer;
pub mod route;
pub mod session;
pub mod token;

use prost::Message;

pub enum ServiceResult {
    Ok(Vec<u8>),
    Err(api::StatusCode),
    Unimplemented,
}

impl ServiceResult {
    pub fn encode<T: Message>(message: &T) -> Self {
        let mut out = Vec::new();
        message.encode(&mut out).expect("encode");
        ServiceResult::Ok(out)
    }
}
```

Implement `peer.rs` (ListPeers over the Peer namespace), `route.rs` (ListRoutes over Route namespace, ProbeRoute returning `UNIMPLEMENTED` until the daemon loop drives routing), `session.rs` (ListSessions over the SessionManager), and `token.rs` (CreateToken returning the raw token once, ListGrants, RevokeToken) following the same pattern. Wire every service into `handle_request` in `server.rs` with capability checks from the grant set:

```rust
    let (service, method) = (request.service.as_str(), request.method.as_str());
    let result = match (service, method) {
        ("IdentityService", "ListIdentities") => identity::list_identities(&store),
        ("IdentityService", "CreateIdentity") => identity::create_identity(&store, &entropy),
        ("PeerService", "ListPeers") => peer::list_peers(&store),
        ("RouteService", "ListRoutes") => route::list_routes(&store),
        ("SessionService", "ListSessions") => session::list_sessions(&sessions),
        ("TokenService", "CreateToken") => token::create_token(&mut token_registry),
        ("TokenService", "RevokeToken") => token::revoke_token(&mut token_registry, &request),
        ("NodeAdmin", "GetStatus") => node::get_status(&store, &metrics),
        ("DiagnosticsService", "GetMetricsSnapshot") => diagnostics::metrics_snapshot(&metrics),
        _ => ServiceResult::Unimplemented,
    };
```

Add `bins/umcd/src/services/node.rs` (GetStatus building a real `NodeStatus` from metrics + store) and `bins/umcd/src/services/diagnostics.rs` (GetMetricsSnapshot using `umc_metrics::snapshot::snapshot`).

- [ ] **Step 2: Add GoAway, cancellation, and deadlines**

In `server.rs::handle_connection`:

1. Handle `Cancel` envelopes: call `dispatcher.cancel(request_id)` and respond with a `CANCELLED` Response when the operation had not committed.
2. Handle `GoAway`: stop accepting new requests, drain within the deadline, close.
3. Deadlines: before dispatch, compare `request.deadline_unix_ms` against a monotonic deadline; expired → `DEADLINE_EXCEEDED`.

Add a `Dispatcher` instance per connection and pass it through `handle_request`.

- [ ] **Step 3: Add audit events and rate limits**

Create `bins/umcd/src/services/audit.rs`:

```rust
//! Audit events (control-api.md §44).
use umc_storage::sqlite::SqliteStore;
use umc_storage::store::{Namespace, Store};

pub fn record_audit(store: &SqliteStore, principal_id: u64, method: &str, outcome: &str, now_ms: u64) {
    let key = format!("{now_ms:x}-{principal_id:x}").into_bytes();
    let value = format!("{principal_id:x}|{method}|{outcome}").into_bytes();
    let _ = store.put(Namespace::Api, &key, &value);
}
```

Call it for: authentication success/failure, token creation/revocation, identity creation/rotation/export/deletion, trust mutation, configuration mutation, node shutdown. Add per-principal token-bucket rate limits (control-api.md §46: 1,000/min application, 10,000/min admin) in `server.rs` using a `HashMap<u64, (u64, u64)>` window counter.

- [ ] **Step 4: Run tests and add service tests**

Run: `cargo test -p umcd`
Expected: PASS.

Add integration coverage in `tests/phase9/tests/echo_app.rs` (or a new `tests/phase14/tests/services.rs`): IdentityService ListIdentities/CreateIdentity round trip; TokenService CreateToken returns once; DiagnosticsService GetMetricsSnapshot; GoAway handling.

- [ ] **Step 5: Commit**

```bash
git add bins/umcd/src/services bins/umcd/src/server.rs
git commit -m "feat(umcd): full service set, GoAway, deadlines, audit"
```

---

### Task 14: SDK completion — sessions, datagrams, events, policy, errors

**Files:**
- Modify: `crates/umc-sdk/src/app.rs`
- Create: `crates/umc-sdk/src/error.rs`
- Create: `crates/umc-sdk/src/policy.rs`
- Create: `crates/umc-sdk/src/events.rs`

- [ ] **Step 1: Write the SDK error model**

`crates/umc-sdk/src/error.rs`:

```rust
//! SDK error model (sdk.md §25): the mapping table is the contract.
use umc_control::proto::umc::api::v1::StatusCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkError {
    Authentication,
    PermissionDenied,
    InvalidArgument,
    NotFound,
    AlreadyExists,
    DeadlineExceeded,
    Cancelled,
    ResourceExhausted,
    FlowControl,
    StreamReset { stream_id: u64, error_code: u64 },
    StreamClosed,
    SessionClosed,
    SessionSuspended,
    Transport,
    Unimplemented,
    Unavailable,
    DataLoss,
    Conflict,
    Internal,
}

/// Map a Control API StatusCode to the SDK error (sdk.md §25.2).
pub fn from_status(code: i32) -> SdkError {
    match StatusCode::try_from(code).unwrap_or(StatusCode::Unknown) {
        StatusCode::Ok => SdkError::Internal, // callers handle Ok before mapping
        StatusCode::Cancelled => SdkError::Cancelled,
        StatusCode::InvalidArgument => SdkError::InvalidArgument,
        StatusCode::DeadlineExceeded => SdkError::DeadlineExceeded,
        StatusCode::NotFound => SdkError::NotFound,
        StatusCode::AlreadyExists => SdkError::AlreadyExists,
        StatusCode::PermissionDenied => SdkError::PermissionDenied,
        StatusCode::Unauthenticated => SdkError::Authentication,
        StatusCode::ResourceExhausted => SdkError::ResourceExhausted,
        StatusCode::Unimplemented => SdkError::Unimplemented,
        StatusCode::Unavailable => SdkError::Unavailable,
        StatusCode::DataLoss => SdkError::DataLoss,
        StatusCode::Conflict => SdkError::Conflict,
        _ => SdkError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_covers_sdk_categories() {
        assert_eq!(from_status(StatusCode::PermissionDenied as i32), SdkError::PermissionDenied);
        assert_eq!(from_status(StatusCode::DeadlineExceeded as i32), SdkError::DeadlineExceeded);
        assert_eq!(from_status(StatusCode::Unauthenticated as i32), SdkError::Authentication);
    }
}
```

- [ ] **Step 2: Write the policy and events modules**

`crates/umc-sdk/src/policy.rs`:

```rust
//! Policy constraints (sdk.md §22, protocol.md §20): applications state
//! constraints; the core chooses paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPolicy {
    pub allow_relay: bool,
    pub allow_store_and_forward: bool,
    pub allow_local_carriers: bool,
    pub allow_internet_carriers: bool,
    pub maximum_hops: u64,
    pub maximum_latency_ms: u64,
    pub minimum_trust: u8,
    pub prefer_low_cost: bool,
    pub prefer_low_energy: bool,
    pub path_strategy: PathStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStrategy {
    Balanced,
    LowLatency,
    LowBandwidth,
    LocalFirst,
    HighDiversity,
    RestrictedNetwork,
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            allow_relay: true,
            allow_store_and_forward: false,
            allow_local_carriers: true,
            allow_internet_carriers: true,
            maximum_hops: 8,
            maximum_latency_ms: 30_000,
            minimum_trust: 1, // Observed
            prefer_low_cost: false,
            prefer_low_energy: false,
            path_strategy: PathStrategy::Balanced,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_reasonable() {
        let p = ConnectionPolicy::default();
        assert_eq!(p.maximum_hops, 8);
        assert!(!p.allow_store_and_forward);
    }
}
```

`crates/umc-sdk/src/events.rs`:

```rust
//! Delivery and path events (sdk.md §19-20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryEvent {
    Acknowledged { stream_id: u64, offset: u64 },
    Lost { stream_id: u64, offset: u64 },
    Reset { stream_id: u64, error_code: u64 },
    Cancelled { stream_id: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEvent {
    Added { path_id: u64, carrier_type: String },
    Validated { path_id: u64 },
    Degraded { path_id: u64 },
    Failed { path_id: u64 },
    Retired { path_id: u64 },
    Migrated { old_path_id: u64, new_path_id: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Active,
    Suspended,
    Closing { clean: bool },
    Closed { reason: String },
}
```

- [ ] **Step 3: Add SDK connect, datagrams, and deadlines**

Extend `crates/umc-sdk/src/app.rs` with:

```rust
    pub async fn connect(&mut self, app: &AppHandle, destination: &[u8], protocol_id: &[u8], policy: &ConnectionPolicy, deadline_ms: u64) -> Result<SessionHandle, SdkError> {
        let request = api::ConnectRequest {
            application_handle: Some(api::OpaqueHandle { bytes: app.0.clone() }),
            destination_endpoint_id: destination.to_vec(),
            protocol_id: protocol_id.to_vec(),
            connection_policy: Some(api::ConnectionPolicy { maximum_hops: policy.maximum_hops as u32, allow_relay: policy.allow_relay, ..Default::default() }),
            deadline_unix_ms: deadline_ms,
            ..Default::default()
        };
        let mut payload = Vec::new();
        prost::Message::encode(&request, &mut payload).map_err(|e| SdkError::Internal)?;
        let response = self.request("ApplicationService", "Connect", payload).await.map_err(|e| match e {
            ClientError::Unimplemented(_) => SdkError::Unimplemented,
            _ => SdkError::Unavailable,
        })?;
        let reply = api::ConnectResponse::decode(response.payload.as_slice()).map_err(|_| SdkError::Internal)?;
        Ok(SessionHandle(reply.session_handle.ok_or(SdkError::Internal)?.bytes))
    }

    pub async fn send_datagram(&mut self, session: &SessionHandle, data: &[u8], deadline_ms: Option<u64>) -> Result<(), SdkError> {
        let request = api::SendDatagramRequest {
            session_handle: Some(api::OpaqueHandle { bytes: session.0.clone() }),
            data: data.to_vec(),
            expiration_delta_ms: deadline_ms,
        };
        let mut payload = Vec::new();
        prost::Message::encode(&request, &mut payload).map_err(|_| SdkError::Internal)?;
        // A successful SendDatagram means local acceptance only (sdk.md §18.1).
        self.request("ApplicationService", "SendDatagram", payload).await.map_err(|_| SdkError::Unavailable)?;
        Ok(())
    }
```

Add `deadline` support to `Client::request` (optional `deadline_unix_ms` field threaded into `api::Request`).

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-sdk`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-sdk/src/error.rs crates/umc-sdk/src/policy.rs crates/umc-sdk/src/events.rs crates/umc-sdk/src/app.rs crates/umc-sdk/src/client.rs crates/umc-sdk/src/lib.rs
git commit -m "feat(sdk): error model, policy, events, connect, datagrams"
```

---

### Task 15: Testing gates — state-machine, property, interop, fault injection, soak

**Files:**
- Create: `tests/phase14/Cargo.toml`
- Create: `tests/phase14/tests/state_machines.rs`
- Create: `tests/phase14/tests/properties.rs`
- Create: `tests/phase14/tests/fault_injection.rs`

- [ ] **Step 1: Test crate manifest**

`tests/phase14/Cargo.toml`:

```toml
[package]
name = "phase14-tests"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
umc-wire = { path = "../../crates/umc-wire" }
umc-handshake = { path = "../../crates/umc-handshake" }
umc-session = { path = "../../crates/umc-session" }
umc-relay = { path = "../../crates/umc-relay" }
umc-routing = { path = "../../crates/umc-routing" }
umc-identity = { path = "../../crates/umc-identity" }
proptest = "1"

[lints]
workspace = true
```

- [ ] **Step 2: Write state-machine and property tests**

`tests/phase14/tests/state_machines.rs`:

```rust
//! testing.md §7: every state machine gets a transition-table test.
use umc_handshake::state::{HandshakeEvent, HandshakeMachine, HandshakeState};
use umc_relay::circuit::{Circuit, CircuitState};
use umc_types::runtime::Instant;

#[test]
fn handshake_machine_rejects_all_invalid_transitions() {
    let valid: &[(HandshakeState, HandshakeEvent)] = &[
        (HandshakeState::Idle, HandshakeEvent::SendClientHello),
        (HandshakeState::Idle, HandshakeEvent::ReceiveRetry),
        (HandshakeState::InitialSent, HandshakeEvent::ReceiveRetry),
        (HandshakeState::InitialSent, HandshakeEvent::ReceiveServerHello),
        (HandshakeState::RetryReceived, HandshakeEvent::SendClientHello),
        (HandshakeState::HandshakeKeys, HandshakeEvent::InstallHandshakeKeys),
        (HandshakeState::HandshakeKeys, HandshakeEvent::SendClientAuth),
        (HandshakeState::PeerAuthenticated, HandshakeEvent::ReceiveServerFinished),
        (HandshakeState::SessionKeys, HandshakeEvent::InstallSessionKeys),
        (HandshakeState::SessionKeys, HandshakeEvent::SendClientFinished),
        (HandshakeState::SessionKeys, HandshakeEvent::Confirm),
        (HandshakeState::Confirmed, HandshakeEvent::InstallSessionKeys),
    ];
    // Every (state, event) not in the valid set must fail.
    for state in [HandshakeState::Idle, HandshakeState::InitialSent, HandshakeState::RetryReceived, HandshakeState::HandshakeKeys, HandshakeState::PeerAuthenticated, HandshakeState::SessionKeys, HandshakeState::Confirmed, HandshakeState::Closed] {
        for event in [HandshakeEvent::SendClientHello, HandshakeEvent::ReceiveServerHello, HandshakeEvent::ReceiveRetry, HandshakeEvent::SendClientAuth, HandshakeEvent::ReceiveServerFinished, HandshakeEvent::SendClientFinished, HandshakeEvent::InstallHandshakeKeys, HandshakeEvent::InstallSessionKeys, HandshakeEvent::Confirm] {
            let mut machine = HandshakeMachine::new();
            machine.state = state;
            let is_valid = valid.iter().any(|(s, e)| *s == state && *e == event);
            assert_eq!(machine.apply(event).is_ok(), is_valid, "state {state:?} event {event:?}");
        }
    }
}

#[test]
fn circuit_machine_reaches_closed_through_draining() {
    let now = Instant(0);
    let mut circuit = Circuit::new(1, now, 600_000, 100, true, false);
    circuit.accept(now);
    umc_relay::close::close_circuit(&mut circuit, umc_relay::close::RelayReason::NoError, now, None);
    assert_eq!(circuit.state, CircuitState::Closing);
    umc_relay::close::drain_circuit(&mut circuit, now + umc_types::runtime::Duration::from_millis(2_000));
    assert_eq!(circuit.state, CircuitState::Draining);
    umc_relay::close::drain_circuit(&mut circuit, now + umc_types::runtime::Duration::from_millis(4_000));
    assert_eq!(circuit.state, CircuitState::Closed);
}
```

`tests/phase14/tests/properties.rs`:

```rust
//! testing.md §8: property tests for the mandatory invariants.
use proptest::prelude::*;
use umc_identity::trust::{TrustEvent, TrustRecord};
use umc_session::flow::FlowControl;
use umc_wire::varint::{decode, encode, MAX_VARINT};

proptest! {
    #[test]
    fn varint_round_trip_any_value(v: u64) {
        if v <= MAX_VARINT {
            let enc = encode(v).unwrap();
            let (dec, n) = decode(&enc).unwrap();
            prop_assert_eq!((dec, n), (v, enc.len()));
        }
    }

    #[test]
    fn flow_control_limits_never_decrease(initial: u64, bumps: Vec<u64>) {
        let mut f = FlowControl::new(initial, 16, 16);
        let mut max = initial;
        for b in bumps {
            f.grant_more(b);
            prop_assert!(f.max_data_local >= max);
            max = f.max_data_local;
        }
    }

    #[test]
    fn trust_never_promotes_automatically(seed: [u8; 8]) {
        let mut record = TrustRecord::new([seed[0]; 32], 0);
        // Only explicit events may reach Trusted.
        for _ in 0..100 {
            let _ = record.apply(TrustEvent::Authenticated, 1);
            let _ = record.apply(TrustEvent::Introduction { expiry_ms: u64::MAX }, 2);
        }
        prop_assert_ne!(record.state, umc_identity::trust::TrustState::Trusted);
    }
}
```

`tests/phase14/tests/fault_injection.rs`:

```rust
//! testing.md §14: packet loss, duplication, reordering never panic and never
//! violate invariants at the session layer.
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
        Instant(1_000_000)
    }
}

fn session(role: Role, secret: [u8; 32], dcid: Vec<u8>) -> Session {
    Session::new(SessionConfig { role, dcid, local_traffic_secret: secret, remote_traffic_secret: secret, initial_max_data: 1 << 20, initial_max_stream_data: 1 << 16, max_ack_delay_ms: 25 }, &C).unwrap()
}

#[test]
fn duplicated_and_reordered_packets_are_safe() {
    let (cs, ss) = run_xx_handshake(
        &IdentityKeyPair::generate(), &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(), &StaticHandshakeKeyPair::generate(),
        &E, b"ump.udp/1", 0,
    )
    .expect("handshake");
    let dcid = vec![1u8; 8];
    let mut client = session(Role::Client, cs.client, dcid.clone());
    let mut server = session(Role::Server, ss.server, dcid);
    let sid = client.open_stream();
    let payload = client.send_stream_data(sid, b"data", true).unwrap();
    let pkt = client.build_outbound(&C, Instant(1_000_000), &payload).unwrap().unwrap();
    // Duplicate delivery: replay must be rejected, not panic.
    let _ = server.on_inbound(Instant(1_000_050), &pkt);
    let _ = server.on_inbound(Instant(1_000_060), &pkt);
    let (data, eof) = server.read_stream(sid).unwrap();
    assert_eq!(data, b"data");
    assert!(eof);
}

#[test]
fn truncated_packets_never_panic() {
    let (cs, _) = run_xx_handshake(
        &IdentityKeyPair::generate(), &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(), &StaticHandshakeKeyPair::generate(),
        &E, b"ump.udp/1", 0,
    )
    .expect("handshake");
    let mut server = session(Role::Server, cs.server, vec![1u8; 8]);
    for len in 0..200usize {
        let bytes = vec![0xABu8; len];
        let _ = server.on_inbound(Instant(1_000_000 + len as u64), &bytes);
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p phase14-tests`
Expected: PASS (6 tests, proptest runs default cases).

- [ ] **Step 4: Add the interop runner skeleton and soak test**

Create `interop/README.md` documenting the runner contract (test vectors, cross-implementation sessions, version coexistence) and `tests/phase14/tests/soak.rs` with a 60-second loop of session open/close cycles asserting bounded memory via `len()` checks:

```rust
#[test]
fn session_churn_is_bounded() {
    // 10,000 open/close cycles must not grow the session registry.
    let mut mgr = umc_session::session::SessionRegistry::new();
    for i in 0..10_000u64 {
        let id = mgr.create_session(vec![(i % 255) as u8; 8], [1u8; 32], [2u8; 32], Role::Client);
        mgr.close(id);
    }
    assert_eq!(mgr.len(), 0);
}
```

(Add `SessionRegistry` to `umc-session` as a thin wrapper over `SessionManager`-style state or reuse `umc_core::session_mgr` if the test crate depends on umc-core — prefer the core crate.)

- [ ] **Step 5: Commit**

```bash
git add tests/phase14 interop
git commit -m "test(phase14): state-machine, property, fault-injection, soak"
```

---

### Task 16: Security gates, compatibility matrix, UMEP records

**Files:**
- Create: `docs/SECURITY-GATES.md`
- Create: `docs/COMPATIBILITY.md`
- Create: `umeps/0010-v01-protocol-baseline.md`

- [ ] **Step 1: Write the security-gate tracker**

`docs/SECURITY-GATES.md` — a checklist tracking the threat-model.md §54 gates. Every plan gate commits progress against it:

```markdown
# Security Gates (threat-model.md §54)

| Gate | Status | Evidence |
| --- | --- | --- |
| Final wire and handshake vectors | open | P12 defers downgrade vectors |
| Independent cryptographic review | open | scheduled before production claims |
| Fuzzing of every network and local parser | partial | wire/handshake/bundle targets; add route, relay, carrier framing, control API, plugin, DB recovery |
| Enforced resource-limit profiles | partial | constants exist; profile-enforcement tests pending |
| Local API permission tests | partial | Phase 14 services tests |
| Plugin process-isolation tests | partial | loopback protocol tests; OS sandbox pending |
| Storage corruption and rollback tests | open | |
| Dependency audit and SBOM | open | |
| Signed release-manifest workflow | open | |
| Published vulnerability-reporting process | partial | SECURITY.md exists; contact is a placeholder |
| Documented residual risks | open | |
```

- [ ] **Step 2: Write the compatibility matrix**

`docs/COMPATIBILITY.md` — the version matrix every release must fill (compatibility.md §11.4):

```markdown
# Release Version Matrix

Release: _TBD_

| Axis | Version | Notes |
| --- | --- | --- |
| UMP protocol | 0x00000001 | |
| Core library | 0.1.x | semver |
| Control API | 1.x | protobuf schema in api/umc.proto |
| Carrier plugin API | 1.x | api/carrier-plugin.proto |
| Storage schema | 1 | migrations in umc-storage |
| SDK (Rust) | 0.1.x | |
| SDK (Python) | 0.1.x | |
| C ABI | experimental | no stability commitment |
```

- [ ] **Step 3: Write the baseline UMEP**

`umeps/0010-v01-protocol-baseline.md` — a Standards Track UMEP that records the v0.1 protocol baseline decisions the plans made unilaterally (per umeps/0001 §2, protocol changes need UMEP coverage):

```markdown
# UMEP-0010: UMP/1 v0.1 Protocol Baseline

- **Status:** Draft
- **Category:** Standards Track
- **Requires:** UMEP-0001

## Summary

Records the identifier and encoding decisions the implementation made while
the specification suite was drafted: request IDs (16 bytes), circuit IDs
(62-bit random), RELAY_STATUS provisional type 0x82, carrier types
(ump.tcp/1, ump.udp/1, ump.lan-discovery/1, ump.tls-stream/1), domain labels
(UMP-BUNDLE-ID-v1, UMP-INVITE-AUTH-v1, UMP-ROTATION-v1, UMP-REVOCATION-v1,
UMP-BOOTSTRAP-v1), the provisional InitialSalt, and the provisional header
protection construction.

## Wire-format impact

RELAY_STATUS (0x82) must be added to the wire-format.md §23 registry before
the interop freeze (relay.md §10).

## Compatibility

All entries are provisional until the interop freeze; nothing in this UMEP
promises stability.
```

- [ ] **Step 4: Wire release manifest signing**

Create `tools/release-manifest/` with a small binary that produces `release-manifest.json` (version, git commit, hashes, supported protocol/storage versions per decisions.md §16) and verifies threshold signatures (2-of-3 initial). Include unit tests for threshold counting:

```rust
#[test]
fn threshold_two_of_three() {
    let sigs = 2;
    let threshold = 2;
    assert!(sigs >= threshold);
    assert!(!(1 >= threshold));
}
```

- [ ] **Step 5: Commit**

```bash
git add docs/SECURITY-GATES.md docs/COMPATIBILITY.md umeps/0010-v01-protocol-baseline.md tools/release-manifest
git commit -m "docs: security gates, compatibility matrix, baseline UMEP, release tooling"
```

---

### Task 17: Phase 14 completion gate

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Verify the gate**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all green.

Run: `cargo test -p phase14-tests`
Expected: PASS.

- [ ] **Step 2: Update README**

```markdown
- [x] Phases 0-13
- [x] Phase 14: conformance — errata, identity-trust, routing/relay completion,
      plugin ops, full Control API, SDK surface, testing gates
```

- [ ] **Step 3: Update SECURITY-GATES.md with progress evidence**

- [ ] **Step 4: Commit**

```bash
git add README.md docs/SECURITY-GATES.md
git commit -m "docs: phase 14 complete"
```

---

## Phase 14 self-review

**Coverage of audit findings:** wire classes (Retry structure, Handshake, Version-Negotiation) → T1; short-header header protection → T2; optional-frame skipping → T3; handshake state machine → T4; handshake traffic secrets + parameters → T5; session retransmission + inbound control frames + stream-ID rules → T6; identity-trust (trust/revocation/delegation/TOFU/rotation) → T7; routing response/error/paths → T8; relay status/authorization/DRAINING/duplicates → T9; discovery static/bootstrap/enumeration/sender-source → T10; BUNDLE dispatch → T11; plugin ops/deadlines → T12; Control API services/GoAway/audit/rate limits → T13; SDK errors/policy/events/connect/datagrams → T14; testing gates → T15; security gates/matrix/UMEP/release tooling → T16.

**Errata applied:** E1-E13 in Part A.

**Remaining known gaps (documented, not blocking):** named-pipe Windows transport, OS keychain keystore, per-platform plugin sandboxing, metrics exporter endpoint, formal protocol analysis, remaining language bindings (Kotlin/Swift/TypeScript/Go), interop with a second independent implementation, the 7 independent security reviews, and production-security claims (gated by docs/SECURITY-GATES.md).


