# Phase 0: Foundations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the Rust workspace and the complete UMP/1 wire-format parser (`umc-types` + `umc-wire`) with test vectors, property tests, fuzzing smoke tests, and Tier-1 CI, so every later phase parses and emits packets against a frozen, fuzzed core.

**Architecture:** Cargo workspace per `decisions.md` §4. `umc-types` holds registry constants and error codes; `umc-wire` is a runtime-independent, dependency-free parser/encoder for varints, byte strings, headers, packet numbers, and every frame in `wire-format.md` §23. The old Go prototype is relocated to `prototype/go/`, not deleted.

**Tech Stack:** Rust (stable, edition 2021), Cargo workspace, std-only runtime (no Tokio in wire crates), proptest (dev-dependency), GitHub Actions CI.

---

## File Structure

- `Cargo.toml` — workspace manifest (members: `crates/umc-types`, `crates/umc-wire`)
- `rust-toolchain.toml` — pin stable
- `rustfmt.toml` — formatting rules
- `clippy.toml` — lint thresholds
- `.gitignore` — target/, prototype artifacts
- `LICENSE-MIT`, `LICENSE-APACHE` — dual license per `decisions.md` §3
- `README.md` — short project pointer
- `.github/workflows/ci.yml` — Tier-1 matrix (ubuntu, macos arm64, windows)
- `prototype/go/` — relocated Go prototype (was `core/`)
- `crates/umc-types/src/lib.rs`, `version.rs`, `frame.rs`, `error.rs`
- `crates/umc-wire/src/lib.rs`, `varint.rs`, `bytes.rs`, `pn.rs`, `header.rs`, `frame.rs`, `packet.rs`
- `crates/umc-wire/src/frames/` — `mod.rs`, `simple.rs` (PADDING, PING, ACK, CONNECTION_CLOSE), `stream.rs` (STREAM, RESET_STREAM, STOP_SENDING), `flow.rs` (MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS), `datagram.rs`, `path.rs` (PATH_CHALLENGE, PATH_RESPONSE, PATH_STATUS, MIGRATE, KEY_UPDATE, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID), `handshake.rs` (AUTH, HANDSHAKE_DATA, CAPABILITIES, SESSION_TICKET), `routing.rs` (ROUTE_REQUEST, ROUTE_RESPONSE, ROUTE_ERROR), `relay.rs` (RELAY_OPEN, RELAY_STATUS, RELAY_DATA, RELAY_CLOSE), `bundle.rs` (BUNDLE, BUNDLE_ACK), `misc.rs` (PEER_HINT, SERVICE_HINT)
- `crates/umc-wire/tests/vectors.rs` — official test vectors
- `crates/umc-wire/tests/fuzz_smoke.rs` — deterministic random-buffer parser soak
- `fuzz/` — cargo-fuzz skeleton (nightly, optional)

---

### Task 1: Workspace scaffolding

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `rustfmt.toml`
- Create: `clippy.toml`
- Create: `.gitignore`
- Create: `README.md`

- [ ] **Step 1: Write the workspace manifest**

```toml
[workspace]
resolver = "2"
members = [
    "crates/umc-types",
    "crates/umc-wire",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"
rust-version = "1.80"

[workspace.lints.rust]
unsafe_code = "deny"
missing_debug_implementations = "warn"

[workspace.lints.clippy]
all = "warn"
pedantic = "warn"

[profile.release]
lto = "thin"
```

- [ ] **Step 2: Pin the toolchain**

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 3: Formatting and lint config**

`rustfmt.toml`:

```toml
edition = "2021"
max_width = 100
use_field_init_shorthand = true
```

`clippy.toml`:

```toml
msrv = "1.80"
```

- [ ] **Step 4: Gitignore**

```gitignore
/target
Cargo.lock
.DS_Store
fuzz/target
```

Note: `Cargo.lock` is ignored for libraries but the workspace lock MUST be committed once the daemon binary exists (Phase 2). Keep it ignored for now.

- [ ] **Step 5: README**

```markdown
# Universal Mesh Core (UMC)

Reference implementation of the Universal Mesh Protocol (UMP/1).
Specifications live in `spec/`. See `spec/decisions.md` for the accepted stack.
```

- [ ] **Step 6: Verify the workspace resolves**

Run: `cargo metadata --no-deps`
Expected: workspace with 0 members resolves (warns about empty members until Task 2 adds crates).

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml rust-toolchain.toml rustfmt.toml clippy.toml .gitignore README.md
git commit -m "chore: scaffold Rust workspace"
```

---

### Task 2: umc-types crate with registry constants

**Files:**
- Create: `crates/umc-types/Cargo.toml`
- Create: `crates/umc-types/src/lib.rs`
- Create: `crates/umc-types/src/version.rs`
- Create: `crates/umc-types/src/frame.rs`
- Create: `crates/umc-types/src/error.rs`

- [ ] **Step 1: Write the failing test for version constants**

Create `crates/umc-types/Cargo.toml`:

```toml
[package]
name = "umc-types"
version.workspace = true
edition.workspace = true
license.workspace = true

[lints]
workspace = true
```

Create `crates/umc-types/src/lib.rs`:

```rust
pub mod error;
pub mod frame;
pub mod version;
```

Create the failing test first — `crates/umc-types/src/version.rs`:

```rust
pub const PROTOCOL_VERSION: u32 = 0x0000_0001;
pub const MAGIC_UMP1: u32 = 0x554D_5031;
pub const MAX_PACKET_SIZE: usize = 65_535;
pub const MAX_CONNECTION_ID_LEN: usize = 20;
pub const MAX_TOKEN_LEN: usize = 1_024;
pub const MAX_GENERIC_BYTE_STRING: usize = 16 * 1024 * 1024;
pub const MIN_INITIAL_UDP: usize = 1_200;
pub const DEFAULT_UDP_MTU: usize = 1_200;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_wire_format_spec() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(MAGIC_UMP1, u32::from_be_bytes(*b"UMP1"));
        assert_eq!(MAX_PACKET_SIZE, 65_535);
        assert_eq!(MAX_CONNECTION_ID_LEN, 20);
        assert_eq!(MAX_TOKEN_LEN, 1_024);
        assert_eq!(MAX_GENERIC_BYTE_STRING, 16 * 1024 * 1024);
        assert_eq!(MIN_INITIAL_UDP, 1_200);
        assert_eq!(DEFAULT_UDP_MTU, 1_200);
    }
}
```

- [ ] **Step 2: Run test to verify it compiles and passes**

Run: `cargo test -p umc-types`
Expected: PASS (1 test).

- [ ] **Step 3: Write the frame-type registry with its test**

`crates/umc-types/src/frame.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameType(pub u64);

impl FrameType {
    pub const PADDING: Self = Self(0x00);
    pub const PING: Self = Self(0x04);
    pub const ACK: Self = Self(0x08);
    pub const CONNECTION_CLOSE: Self = Self(0x0C);
    pub const STREAM: Self = Self(0x10);
    pub const RESET_STREAM: Self = Self(0x14);
    pub const STOP_SENDING: Self = Self(0x18);
    pub const MAX_DATA: Self = Self(0x1C);
    pub const MAX_STREAM_DATA: Self = Self(0x20);
    pub const MAX_STREAMS: Self = Self(0x24);
    pub const DATAGRAM: Self = Self(0x28);
    pub const NEW_CONNECTION_ID: Self = Self(0x2C);
    pub const RETIRE_CONNECTION_ID: Self = Self(0x30);
    pub const PATH_CHALLENGE: Self = Self(0x34);
    pub const PATH_RESPONSE: Self = Self(0x38);
    pub const PATH_STATUS: Self = Self(0x3C);
    pub const MIGRATE: Self = Self(0x40);
    pub const KEY_UPDATE: Self = Self(0x44);
    pub const ROUTE_REQUEST: Self = Self(0x48);
    pub const ROUTE_RESPONSE: Self = Self(0x4C);
    pub const ROUTE_ERROR: Self = Self(0x50);
    pub const RELAY_OPEN: Self = Self(0x54);
    pub const RELAY_DATA: Self = Self(0x58);
    pub const RELAY_CLOSE: Self = Self(0x5C);
    pub const BUNDLE: Self = Self(0x60);
    pub const BUNDLE_ACK: Self = Self(0x64);
    pub const PEER_HINT: Self = Self(0x68);
    pub const CAPABILITIES: Self = Self(0x6C);
    pub const AUTH: Self = Self(0x70);
    pub const HANDSHAKE_DATA: Self = Self(0x74);
    pub const SESSION_TICKET: Self = Self(0x78);
    pub const SERVICE_HINT: Self = Self(0x7C);
    pub const RELAY_STATUS: Self = Self(0x82);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionBehavior {
    CriticalFixed,
    OptionalFixed,
    CriticalLengthDelimited,
    OptionalLengthDelimited,
}

impl FrameType {
    pub fn behavior(self) -> ExtensionBehavior {
        match self.0 & 0b11 {
            0b00 => ExtensionBehavior::CriticalFixed,
            0b01 => ExtensionBehavior::OptionalFixed,
            0b10 => ExtensionBehavior::CriticalLengthDelimited,
            _ => ExtensionBehavior::OptionalLengthDelimited,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_frame_types_are_critical_fixed_layout() {
        // All v0.1 registry frames are `..00` or `..10`; fixed-layout ones must
        // be rejected by receivers that do not know them (wire-format §22).
        assert_eq!(FrameType::PADDING.behavior(), ExtensionBehavior::CriticalFixed);
        assert_eq!(FrameType::PING.behavior(), ExtensionBehavior::CriticalFixed);
        assert_eq!(FrameType::ACK.behavior(), ExtensionBehavior::CriticalFixed);
        assert_eq!(FrameType::ROUTE_REQUEST.behavior(), ExtensionBehavior::CriticalLengthDelimited);
        assert_eq!(FrameType::RELAY_STATUS.behavior(), ExtensionBehavior::CriticalLengthDelimited);
        assert_eq!(FrameType::BUNDLE.behavior(), ExtensionBehavior::CriticalLengthDelimited);
    }

    #[test]
    fn unknown_optional_length_delimited_is_skippable() {
        let t = FrameType(0x0F); // ..11
        assert_eq!(t.behavior(), ExtensionBehavior::OptionalLengthDelimited);
        let t = FrameType(0x01); // ..01
        assert_eq!(t.behavior(), ExtensionBehavior::OptionalFixed);
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-types`
Expected: PASS (3 tests).

- [ ] **Step 5: Write the transport error-code registry with its test**

`crates/umc-types/src/error.rs`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportError(pub u64);

impl TransportError {
    pub const NO_ERROR: Self = Self(0x00);
    pub const INTERNAL_ERROR: Self = Self(0x01);
    pub const PROTOCOL_VIOLATION: Self = Self(0x02);
    pub const FRAME_ENCODING_ERROR: Self = Self(0x03);
    pub const UNSUPPORTED_VERSION: Self = Self(0x04);
    pub const UNSUPPORTED_FRAME: Self = Self(0x05);
    pub const CRYPTO_ERROR: Self = Self(0x06);
    pub const AUTHENTICATION_FAILED: Self = Self(0x07);
    pub const REPLAY_DETECTED: Self = Self(0x08);
    pub const FLOW_CONTROL_ERROR: Self = Self(0x09);
    pub const STREAM_LIMIT_ERROR: Self = Self(0x0A);
    pub const CONNECTION_ID_ERROR: Self = Self(0x0B);
    pub const PATH_VALIDATION_FAILED: Self = Self(0x0C);
    pub const ROUTE_NOT_FOUND: Self = Self(0x0D);
    pub const ROUTE_LOOP: Self = Self(0x0E);
    pub const RELAY_REFUSED: Self = Self(0x0F);
    pub const RESOURCE_LIMIT: Self = Self(0x10);
    pub const STORAGE_LIMIT: Self = Self(0x11);
    pub const EXPIRED: Self = Self(0x12);
    pub const POLICY_REJECTED: Self = Self(0x13);
    pub const CARRIER_FAILURE: Self = Self(0x14);
    pub const HANDSHAKE_TIMEOUT: Self = Self(0x15);
    pub const IDLE_TIMEOUT: Self = Self(0x16);
    pub const KEY_UPDATE_ERROR: Self = Self(0x17);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_match_wire_format_registry() {
        assert_eq!(TransportError::NO_ERROR.0, 0x00);
        assert_eq!(TransportError::PROTOCOL_VIOLATION.0, 0x02);
        assert_eq!(TransportError::KEY_UPDATE_ERROR.0, 0x17);
    }
}
```

- [ ] **Step 6: Run full crate tests and commit**

Run: `cargo test -p umc-types && cargo clippy -p umc-types -- -D warnings`
Expected: PASS, clippy clean.

```bash
git add crates/umc-types
git commit -m "feat(types): protocol constants, frame registry, error codes"
```

---

### Task 3: Varint encoding and decoding

**Files:**
- Create: `crates/umc-wire/Cargo.toml`
- Create: `crates/umc-wire/src/lib.rs`
- Create: `crates/umc-wire/src/varint.rs`

- [ ] **Step 1: Crate manifest (proptest dev-dependency)**

`crates/umc-wire/Cargo.toml`:

```toml
[package]
name = "umc-wire"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
umc-types = { path = "../umc-types" }

[dev-dependencies]
proptest = "1"

[lints]
workspace = true
```

`crates/umc-wire/src/lib.rs`:

```rust
pub mod bytes;
pub mod frame;
pub mod header;
pub mod packet;
pub mod pn;
pub mod varint;
```

- [ ] **Step 2: Write the failing varint test**

`crates/umc-wire/src/varint.rs`:

```rust
use umc_types::frame::FrameType;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    ValueTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    NonCanonical,
    Overflow,
}

pub const MAX_VARINT: u64 = 4_611_686_018_427_387_903;

pub fn encode_into(out: &mut Vec<u8>, v: u64) -> Result<(), EncodeError> {
    if v <= 63 {
        out.push(v as u8);
    } else if v <= 16_383 {
        out.push(0b0100_0000 | ((v >> 8) as u8));
        out.push(v as u8);
    } else if v <= 1_073_741_823 {
        out.push(0b1000_0000 | ((v >> 24) as u8));
        out.extend_from_slice(&(v as u32).to_be_bytes());
    } else if v <= MAX_VARINT {
        out.push(0b1100_0000 | ((v >> 56) as u8));
        out.extend_from_slice(&v.to_be_bytes());
    } else {
        return Err(EncodeError::ValueTooLarge);
    }
    Ok(())
}

pub fn encode(v: u64) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::with_capacity(9);
    encode_into(&mut out, v)?;
    Ok(out)
}

pub fn decode(buf: &[u8]) -> Result<(u64, usize), DecodeError> {
    let first = *buf.first().ok_or(DecodeError::Truncated)?;
    let width = match first >> 6 {
        0 => 1usize,
        1 => 2usize,
        2 => 4usize,
        _ => 8usize,
    };
    if buf.len() < width {
        return Err(DecodeError::Truncated);
    }
    let mut raw = [0u8; 8];
    raw[..width].copy_from_slice(&buf[..width]);
    raw[0] &= 0x3F;
    let v = u64::from_be_bytes(raw);
    match width {
        2 if v <= 63 => return Err(DecodeError::NonCanonical),
        4 if v <= 16_383 => return Err(DecodeError::NonCanonical),
        8 if v <= 1_073_741_823 => return Err(DecodeError::NonCanonical),
        _ => {}
    }
    Ok((v, width))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_round_trips() {
        for v in [0u64, 1, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824, MAX_VARINT] {
            let enc = encode(v).unwrap();
            let (dec, n) = decode(&enc).unwrap();
            assert_eq!((dec, n), (v, enc.len()), "value {v}");
        }
    }

    #[test]
    fn encoding_widths_match_spec() {
        assert_eq!(encode(0).unwrap(), vec![0x00]);
        assert_eq!(encode(63).unwrap(), vec![0x3F]);
        assert_eq!(encode(64).unwrap(), vec![0x40, 0x40]);
        assert_eq!(encode(16_383).unwrap(), vec![0x7F, 0xFF]);
        assert_eq!(encode(1_073_741_824).unwrap(), vec![0x80, 0x40, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn rejects_non_canonical_encodings() {
        assert_eq!(decode(&[0x40, 0x00]).unwrap_err(), DecodeError::NonCanonical);
        assert_eq!(decode(&[0x80, 0x00, 0x00, 0x00]).unwrap_err(), DecodeError::NonCanonical);
        assert_eq!(decode(&[0xC0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(), DecodeError::NonCanonical);
    }

    #[test]
    fn rejects_truncated_and_oversized() {
        assert_eq!(decode(&[]).unwrap_err(), DecodeError::Truncated);
        assert_eq!(decode(&[0x40]).unwrap_err(), DecodeError::Truncated);
        assert_eq!(encode(MAX_VARINT + 1).unwrap_err(), EncodeError::ValueTooLarge);
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p umc-wire varint`
Expected: FAIL — compile errors, code not implemented yet (encode/decode bodies exist in the draft above; write the full file exactly as shown, then the tests pass; if starting from stubs, expect `function not found` style failures first).

- [ ] **Step 4: Implement the full module (above), run tests**

Run: `cargo test -p umc-wire`
Expected: PASS (4 varint tests).

- [ ] **Step 5: Add property tests (canonical round-trip over random values)**

Append to `varint.rs`:

```rust
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn round_trip_any_value(v: u64) {
            if v <= MAX_VARINT {
                let enc = encode(v).unwrap();
                let (dec, n) = decode(&enc).unwrap();
                assert_eq!((dec, n), (v, enc.len()));
            } else {
                assert_eq!(encode(v), Err(EncodeError::ValueTooLarge));
            }
        }
    }
}
```

Run: `cargo test -p umc-wire`
Expected: PASS (5 tests, proptest runs 256 default cases).

- [ ] **Step 6: Commit**

```bash
git add crates/umc-wire
git commit -m "feat(wire): canonical prefix varints"
```

---

### Task 4: Length-prefixed byte strings

**Files:**
- Create: `crates/umc-wire/src/bytes.rs`

- [ ] **Step 1: Write the failing test**

```rust
use crate::varint::{decode as decode_varint, encode_into};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytesError {
    VarintTooLarge,
    LengthExceedsLimit,
    Truncated,
}

/// Encode a length-prefixed byte string (wire-format §6).
pub fn encode(out: &mut Vec<u8>, value: &[u8], limit: usize) -> Result<(), BytesError> {
    if value.len() > limit {
        return Err(BytesError::LengthExceedsLimit);
    }
    encode_into(out, value.len() as u64).map_err(|_| BytesError::VarintTooLarge)?;
    out.extend_from_slice(value);
    Ok(())
}

/// Decode a length-prefixed byte string. Returns (value, bytes_consumed).
pub fn decode(buf: &[u8], limit: usize) -> Result<(&[u8], usize), BytesError> {
    let (len, n) = decode_varint(buf).map_err(|_| BytesError::Truncated)?;
    if len > limit as u64 {
        return Err(BytesError::LengthExceedsLimit);
    }
    let len = len as usize;
    let total = n.checked_add(len).ok_or(BytesError::Truncated)?;
    if buf.len() < total {
        return Err(BytesError::Truncated);
    }
    Ok((&buf[n..total], total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut out = Vec::new();
        encode(&mut out, b"hello", 1024).unwrap();
        let (v, n) = decode(&out, 1024).unwrap();
        assert_eq!((v, n), (&b"hello"[..], out.len()));
    }

    #[test]
    fn empty_string_is_valid() {
        let mut out = Vec::new();
        encode(&mut out, b"", 1024).unwrap();
        assert_eq!(out, vec![0x00]);
        let (v, _) = decode(&out, 1024).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn rejects_oversize_before_allocation() {
        let mut out = Vec::new();
        assert_eq!(encode(&mut out, &[0u8; 5], 4), Err(BytesError::LengthExceedsLimit));
        // Declared length larger than the buffer and larger than limit.
        assert_eq!(decode(&[0x40, 0x40], 3), Err(BytesError::LengthExceedsLimit));
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(decode(&[0x40, 0x40, 0x01], 1024), Err(BytesError::Truncated));
        assert_eq!(decode(&[], 1024), Err(BytesError::Truncated));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p umc-wire bytes`
Expected: FAIL — module not implemented (`bytes` not declared in lib.rs).

- [ ] **Step 3: Add the module to lib.rs, run tests**

Add `pub mod bytes;` to `crates/umc-wire/src/lib.rs`, write the file exactly as above.

Run: `cargo test -p umc-wire`
Expected: PASS (4 byte-string tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/src/bytes.rs crates/umc-wire/src/lib.rs
git commit -m "feat(wire): length-prefixed byte strings"
```

---

### Task 5: Packet-number reconstruction

**Files:**
- Create: `crates/umc-wire/src/pn.rs`

- [ ] **Step 1: Write the failing test**

```rust
use umc_types::version::MAX_PACKET_SIZE;

pub const MAX_PACKET_NUMBER: u64 = (1 << 62) - 1;

/// Reconstruct a truncated packet number (session.md §8.1).
/// `expected` is `largest_received + 1` in the same space.
pub fn reconstruct(truncated: u64, bits: u32, expected: u64) -> Result<u64, PnError> {
    if bits == 0 || bits > 62 {
        return Err(PnError::InvalidBits);
    }
    if truncated >= (1u64 << bits) {
        return Err(PnError::TruncatedTooLarge);
    }
    let window = 1u64 << bits;
    let half = window >> 1;
    let mask = window - 1;
    let mut candidate = (expected & !mask) | truncated;
    if candidate + half <= expected && candidate + window <= MAX_PACKET_NUMBER {
        candidate += window;
    } else if candidate > expected + half && candidate >= window {
        candidate -= window;
    }
    if candidate > MAX_PACKET_NUMBER {
        return Err(PnError::Overflow);
    }
    Ok(candidate)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnError {
    InvalidBits,
    TruncatedTooLarge,
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_when_in_window() {
        assert_eq!(reconstruct(100, 8, 101).unwrap(), 100);
        assert_eq!(reconstruct(0, 1, 1).unwrap(), 0);
    }

    #[test]
    fn rolls_forward_across_window_boundary() {
        // expected 255, truncated 1 (8 bits): candidate 257 is nearest.
        assert_eq!(reconstruct(1, 8, 255).unwrap(), 257);
        // expected 100, truncated 90: 90 is nearer than 346.
        assert_eq!(reconstruct(90, 8, 100).unwrap(), 90);
    }

    #[test]
    fn rolls_back_when_behind() {
        // expected 400, truncated 200: 456 is nearer than 200.
        assert_eq!(reconstruct(200, 8, 400).unwrap(), 456);
    }

    #[test]
    fn rejects_invalid_input() {
        assert_eq!(reconstruct(0, 0, 1), Err(PnError::InvalidBits));
        assert_eq!(reconstruct(1, 1, 1), Err(PnError::TruncatedTooLarge));
        assert_eq!(reconstruct(0, 63, 0), Err(PnError::InvalidBits));
    }

    #[test]
    fn rejects_overflow() {
        assert_eq!(
            reconstruct(MAX_PACKET_NUMBER, 62, MAX_PACKET_NUMBER),
            Err(PnError::Overflow)
        );
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p umc-wire pn`
Expected: FAIL — module missing.

- [ ] **Step 3: Add module to lib.rs, implement, run**

Add `pub mod pn;` to lib.rs; write the file as above.

Run: `cargo test -p umc-wire`
Expected: PASS (5 packet-number tests).

Note: `MAX_PACKET_SIZE` import is unused in this module — remove it from the import line to keep clippy clean.

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/src/pn.rs crates/umc-wire/src/lib.rs
git commit -m "feat(wire): truncated packet-number reconstruction"
```

---

### Task 6: Header form byte and long header

**Files:**
- Create: `crates/umc-wire/src/header.rs`

- [ ] **Step 1: Write the failing test**

```rust
use umc_types::version::{MAX_CONNECTION_ID_LEN, MAX_TOKEN_LEN, PROTOCOL_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderForm {
    Long,
    Short,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongPacketType {
    Initial,
    Retry,
    Handshake,
    VersionNegotiation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortPacketSpace {
    SessionData,
    PathControl,
    RelayData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    ReservedBits,
    InvalidType,
    InvalidSpace,
    ConnectionIdTooLong,
    TokenTooLong,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderByte {
    pub long: bool,
    pub kind: u8,
    pub key_phase: bool,
    pub pn_bits: u32,
}

impl HeaderByte {
    pub const LONG_INITIAL: Self = Self { long: true, kind: 0, key_phase: false, pn_bits: 2 };
    pub const LONG_RETRY: Self = Self { long: true, kind: 1, key_phase: false, pn_bits: 2 };
    pub const LONG_HANDSHAKE: Self = Self { long: true, kind: 2, key_phase: false, pn_bits: 2 };
    pub const LONG_VERSION_NEGOTIATION: Self = Self { long: true, kind: 3, key_phase: false, pn_bits: 2 };
    pub const SHORT_SESSION: Self = Self { long: false, kind: 0, key_phase: false, pn_bits: 2 };
    pub const SHORT_PATH: Self = Self { long: false, kind: 1, key_phase: false, pn_bits: 2 };
    pub const SHORT_RELAY: Self = Self { long: false, kind: 2, key_phase: false, pn_bits: 2 };

    pub fn encode(&self) -> u8 {
        let mut b = 0u8;
        if self.long {
            b |= 0x80;
        }
        b |= (self.kind & 0x03) << 5;
        if self.key_phase {
            b |= 0x10;
        }
        b |= (self.pn_bits as u8 & 0x03) << 2;
        b
    }

    pub fn decode(b: u8) -> Result<Self, HeaderError> {
        if b & 0x03 != 0 {
            return Err(HeaderError::ReservedBits);
        }
        let pn_bits = match (b >> 2) & 0x03 {
            0 => 8u32,
            1 => 16,
            2 => 32,
            _ => 64,
        };
        Ok(Self {
            long: b & 0x80 != 0,
            kind: (b >> 5) & 0x03,
            key_phase: b & 0x10 != 0,
            pn_bits,
        })
    }

    pub fn long_type(&self) -> Option<LongPacketType> {
        if !self.long {
            return None;
        }
        match self.kind {
            0 => Some(LongPacketType::Initial),
            1 => Some(LongPacketType::Retry),
            2 => Some(LongPacketType::Handshake),
            _ => Some(LongPacketType::VersionNegotiation),
        }
    }

    pub fn short_space(&self) -> Option<ShortPacketSpace> {
        if self.long {
            return None;
        }
        match self.kind {
            0 => Some(ShortPacketSpace::SessionData),
            1 => Some(ShortPacketSpace::PathControl),
            2 => Some(ShortPacketSpace::RelayData),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeader {
    pub ptype: LongPacketType,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub payload_len: u64,
    pub packet_number: u64,
    pub pn_bits: u32,
}

impl LongHeader {
    pub fn encode(&self) -> Result<Vec<u8>, HeaderError> {
        if self.dcid.len() > MAX_CONNECTION_ID_LEN || self.scid.len() > MAX_CONNECTION_ID_LEN {
            return Err(HeaderError::ConnectionIdTooLong);
        }
        if self.token.len() > MAX_TOKEN_LEN {
            return Err(HeaderError::TokenTooLong);
        }
        let mut out = Vec::new();
        let hb = match self.ptype {
            LongPacketType::Initial => HeaderByte::LONG_INITIAL,
            LongPacketType::Retry => HeaderByte::LONG_RETRY,
            LongPacketType::Handshake => HeaderByte::LONG_HANDSHAKE,
            LongPacketType::VersionNegotiation => HeaderByte::LONG_VERSION_NEGOTIATION,
        };
        out.push(hb.encode());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(&self.dcid);
        out.push(self.scid.len() as u8);
        out.extend_from_slice(&self.scid);
        crate::varint::encode_into(&mut out, self.token.len() as u64).map_err(|_| HeaderError::Truncated)?;
        out.extend_from_slice(&self.token);
        crate::varint::encode_into(&mut out, self.payload_len).map_err(|_| HeaderError::Truncated)?;
        let pn_bytes = (self.pn_bits as usize) / 8;
        out.extend_from_slice(&self.packet_number.to_be_bytes()[8 - pn_bytes..]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_byte_round_trip() {
        for hb in [
            HeaderByte::LONG_INITIAL,
            HeaderByte::LONG_HANDSHAKE,
            HeaderByte::SHORT_SESSION,
            HeaderByte::SHORT_PATH,
            HeaderByte::SHORT_RELAY,
        ] {
            assert_eq!(HeaderByte::decode(hb.encode()).unwrap(), hb);
        }
    }

    #[test]
    fn rejects_reserved_bits() {
        assert_eq!(HeaderByte::decode(0x01), Err(HeaderError::ReservedBits));
    }

    #[test]
    fn pn_bits_map_to_byte_lengths() {
        let hb = HeaderByte::decode(0b0000_0000).unwrap();
        assert_eq!(hb.pn_bits, 8);
        let hb = HeaderByte::decode(0b0000_0100).unwrap();
        assert_eq!(hb.pn_bits, 16);
    }

    #[test]
    fn long_header_round_trip() {
        let h = LongHeader {
            ptype: LongPacketType::Initial,
            version: PROTOCOL_VERSION,
            dcid: vec![1, 2, 3, 4, 5, 6, 7, 8],
            scid: vec![9, 10, 11, 12, 13, 14, 15, 16],
            token: vec![],
            payload_len: 64,
            packet_number: 42,
            pn_bits: 16,
        };
        let enc = h.encode().unwrap();
        assert_eq!(enc[0], 0b1000_0000);
        assert_eq!(&enc[1..5], &PROTOCOL_VERSION.to_be_bytes());
        assert_eq!(enc[5], 8);
        assert_eq!(enc[6 + 8 + 1], 8);
    }

    #[test]
    fn rejects_oversized_ids() {
        let h = LongHeader {
            ptype: LongPacketType::Initial,
            version: PROTOCOL_VERSION,
            dcid: vec![0u8; 21],
            scid: vec![],
            token: vec![],
            payload_len: 0,
            packet_number: 0,
            pn_bits: 8,
        };
        assert_eq!(h.encode(), Err(HeaderError::ConnectionIdTooLong));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p umc-wire header`
Expected: FAIL — module missing.

- [ ] **Step 3: Add module to lib.rs, implement, run**

Add `pub mod header;` to lib.rs; write the file as above.

Run: `cargo test -p umc-wire`
Expected: PASS (5 header tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/src/header.rs crates/umc-wire/src/lib.rs
git commit -m "feat(wire): header form byte and long header encoding"
```

---

### Task 7: Short header

**Files:**
- Modify: `crates/umc-wire/src/header.rs`

- [ ] **Step 1: Append the short-header type and tests**

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortHeader {
    pub space: ShortPacketSpace,
    pub dcid: Vec<u8>,
    pub path_id: u64,
    pub packet_number: u64,
    pub pn_bits: u32,
    pub key_phase: bool,
}

impl ShortHeader {
    pub fn encode(&self) -> Result<Vec<u8>, HeaderError> {
        if self.dcid.len() > MAX_CONNECTION_ID_LEN {
            return Err(HeaderError::ConnectionIdTooLong);
        }
        let mut out = Vec::new();
        let mut hb = match self.space {
            ShortPacketSpace::SessionData => HeaderByte::SHORT_SESSION,
            ShortPacketSpace::PathControl => HeaderByte::SHORT_PATH,
            ShortPacketSpace::RelayData => HeaderByte::SHORT_RELAY,
        };
        hb.key_phase = self.key_phase;
        hb.pn_bits = self.pn_bits;
        out.push(hb.encode());
        out.extend_from_slice(&self.dcid);
        crate::varint::encode_into(&mut out, self.path_id).map_err(|_| HeaderError::Truncated)?;
        let pn_bytes = (self.pn_bits as usize) / 8;
        out.extend_from_slice(&self.packet_number.to_be_bytes()[8 - pn_bytes..]);
        Ok(out)
    }
}
```

Append tests:

```rust
    #[test]
    fn short_header_round_trip() {
        let h = ShortHeader {
            space: ShortPacketSpace::SessionData,
            dcid: vec![1, 2, 3, 4, 5, 6, 7, 8],
            path_id: 1,
            packet_number: 4021,
            pn_bits: 16,
            key_phase: false,
        };
        let enc = h.encode().unwrap();
        assert_eq!(enc[0], 0b0000_0000);
        assert_eq!(&enc[9..], &0x0F, "path id 1 then pn 4021 bytes");
        let space = HeaderByte::decode(enc[0]).unwrap().short_space().unwrap();
        assert_eq!(space, ShortPacketSpace::SessionData);
    }
```

Note: `4021 = 0x0FB5`, so the last two bytes are `0x0F 0xB5`; `path_id = 1` encodes as `0x01`. The assertion above checks `&enc[9..] == &[0x01, 0x0F, 0xB5]`. Write the assertion literally:

```rust
        assert_eq!(&enc[9..], &[0x01, 0x0F, 0xB5]);
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-wire header`
Expected: PASS (6 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-wire/src/header.rs
git commit -m "feat(wire): short header encoding"
```

---

### Task 8: Frame dispatch with extension rules

**Files:**
- Create: `crates/umc-wire/src/frame.rs`
- Create: `crates/umc-wire/src/frames/mod.rs`
- Create: `crates/umc-wire/src/frames/simple.rs` (PADDING, PING, ACK, CONNECTION_CLOSE)

- [ ] **Step 1: Write the failing dispatch test**

`crates/umc-wire/src/frame.rs`:

```rust
use umc_types::frame::{ExtensionBehavior, FrameType};

pub const MAX_ACK_RANGES: usize = 64;
pub const MAX_REASON_LEN: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    UnknownCriticalFrame(FrameType),
    UnknownOptionalFixedFrame(FrameType),
    InvalidPadding,
    AckRangeUnderflow,
    TooManyAckRanges,
    AckDelayTooLarge,
    Varint(crate::varint::DecodeError),
    Truncated,
    LengthExceedsLimit,
    UnsupportedLengthDelimited,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    pub gap: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding,
    Ping,
    Ack(AckFrame),
    ConnectionClose(ConnectionCloseFrame),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFrame {
    pub largest_acknowledged: u64,
    pub ack_delay: u64,
    pub first_ack_range: u64,
    pub additional_ranges: Vec<AckRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionCloseFrame {
    pub error_code: u64,
    pub trigger_frame_type: u64,
    pub reason: Vec<u8>,
}

impl AckFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.additional_ranges.len() > MAX_ACK_RANGES {
            return Err(FrameError::TooManyAckRanges);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::ACK.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.largest_acknowledged).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.ack_delay).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, (self.additional_ranges.len() + 1) as u64)
            .map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.first_ack_range).map_err(FrameError::Varint)?;
        for r in &self.additional_ranges {
            crate::varint::encode_into(&mut out, r.gap).map_err(FrameError::Varint)?;
            crate::varint::encode_into(&mut out, r.length).map_err(FrameError::Varint)?;
        }
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let largest = read_varint(&mut pos)?;
        let delay = read_varint(&mut pos)?;
        let range_count = read_varint(&mut pos)?;
        if range_count == 0 || range_count as usize > MAX_ACK_RANGES + 1 {
            return Err(FrameError::TooManyAckRanges);
        }
        let first = read_varint(&mut pos)?;
        let mut ranges = Vec::new();
        for _ in 1..range_count {
            let gap = read_varint(&mut pos)?;
            let length = read_varint(&mut pos)?;
            if length == 0 {
                return Err(FrameError::AckRangeUnderflow);
            }
            ranges.push(AckRange { gap, length });
        }
        Ok((Self { largest_acknowledged: largest, ack_delay: delay, first_ack_range: first, additional_ranges: ranges }, pos))
    }
}

impl ConnectionCloseFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.reason.len() > MAX_REASON_LEN {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::CONNECTION_CLOSE.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.error_code).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.trigger_frame_type).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.reason, MAX_REASON_LEN).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let code = read_varint(&mut pos)?;
        let trigger = read_varint(&mut pos)?;
        let (reason, n) = crate::bytes::decode(&body[pos..], MAX_REASON_LEN).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((Self { error_code: code, trigger_frame_type: trigger, reason: reason.to_vec() }, pos))
    }
}

/// Parse frames from a decrypted payload (wire-format §20-22).
pub fn decode_frames(payload: &[u8]) -> Result<Vec<Frame>, FrameError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        let (raw_ty, n) = crate::varint::decode(&payload[pos..]).map_err(FrameError::Varint)?;
        pos += n;
        let ty = FrameType(raw_ty);
        match ty.behavior() {
            ExtensionBehavior::CriticalFixed | ExtensionBehavior::OptionalFixed => {
                let rest = &payload[pos..];
                match ty {
                    FrameType::PADDING => {
                        // Each zero byte is one PADDING frame.
                        if rest.first() != Some(&0) {
                            return Err(FrameError::InvalidPadding);
                        }
                        out.push(Frame::Padding);
                        pos += 1;
                    }
                    FrameType::PING => {
                        out.push(Frame::Ping);
                    }
                    FrameType::ACK => {
                        let (f, used) = AckFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::Ack(f));
                    }
                    FrameType::CONNECTION_CLOSE => {
                        let (f, used) = ConnectionCloseFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::ConnectionClose(f));
                    }
                    _ if ty.behavior() == ExtensionBehavior::OptionalFixed => {
                        return Err(FrameError::UnknownOptionalFixedFrame(ty));
                    }
                    _ => return Err(FrameError::UnknownCriticalFrame(ty)),
                }
            }
            ExtensionBehavior::CriticalLengthDelimited | ExtensionBehavior::OptionalLengthDelimited => {
                return Err(FrameError::UnsupportedLengthDelimited);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_round_trip() {
        assert_eq!(decode_frames(&[0x04]).unwrap(), vec![Frame::Ping]);
    }

    #[test]
    fn padding_is_one_byte_per_frame() {
        assert_eq!(decode_frames(&[0x00, 0x00, 0x00]).unwrap(), vec![Frame::Padding, Frame::Padding, Frame::Padding]);
    }

    #[test]
    fn non_zero_padding_byte_is_an_error() {
        assert_eq!(decode_frames(&[0x00, 0x01]), Err(FrameError::UnknownCriticalFrame(FrameType(0x01))));
    }

    #[test]
    fn ack_round_trip_with_ranges() {
        let f = AckFrame { largest_acknowledged: 100, ack_delay: 5, first_ack_range: 3, additional_ranges: vec![AckRange { gap: 2, length: 4 }] };
        let enc = f.encode().unwrap();
        let (dec, used) = AckFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn ack_rejects_zero_length_range() {
        let enc = [0x08, 0x64, 0x05, 0x02, 0x03, 0x02, 0x00];
        assert_eq!(decode_frames(&enc), Err(FrameError::AckRangeUnderflow));
    }

    #[test]
    fn connection_close_round_trip() {
        let f = ConnectionCloseFrame { error_code: 0x02, trigger_frame_type: 0x10, reason: b"bad stream".to_vec() };
        let enc = f.encode().unwrap();
        let (dec, used) = ConnectionCloseFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn unknown_optional_fixed_is_rejected() {
        assert_eq!(decode_frames(&[0x01]), Err(FrameError::UnknownOptionalFixedFrame(FrameType(0x01))));
    }
}
```

`crates/umc-wire/src/frames/mod.rs` (empty for now; filled in Tasks 9-14):

```rust
// Frame implementations grouped by function. See wire-format.md §23.
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p umc-wire frame`
Expected: FAIL — module missing.

- [ ] **Step 3: Add modules to lib.rs, implement, run**

Add `pub mod frame;` and `pub mod frames;` to lib.rs; write the files as above.

Run: `cargo test -p umc-wire`
Expected: PASS (7 frame tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/src/frame.rs crates/umc-wire/src/frames crates/umc-wire/src/lib.rs
git commit -m "feat(wire): frame dispatch, ACK, CONNECTION_CLOSE, PADDING, PING"
```

---

### Task 9: STREAM, RESET_STREAM, STOP_SENDING frames

**Files:**
- Create: `crates/umc-wire/src/frames/stream.rs`

- [ ] **Step 1: Write the failing test and implementation**

`crates/umc-wire/src/frames/stream.rs`:

```rust
use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_PROTOCOL_ID_LEN: usize = 255;
pub const MAX_STREAM_METADATA_LEN: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFrame {
    pub stream_id: u64,
    pub fin: bool,
    pub offset_present: bool,
    pub len_present: bool,
    pub open: bool,
    pub unidirectional: bool,
    pub offset: u64,
    pub data: Vec<u8>,
    pub protocol_id: Vec<u8>,
    pub metadata: Vec<u8>,
}

impl StreamFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::STREAM.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.stream_id).map_err(FrameError::Varint)?;
        let mut flags = 0u8;
        if self.fin { flags |= 0x01; }
        if self.offset_present { flags |= 0x02; }
        if self.len_present { flags |= 0x04; }
        if self.open { flags |= 0x08; }
        if self.unidirectional { flags |= 0x10; }
        out.push(flags);
        if self.offset_present {
            crate::varint::encode_into(&mut out, self.offset).map_err(FrameError::Varint)?;
        }
        if self.len_present {
            crate::varint::encode_into(&mut out, self.data.len() as u64).map_err(FrameError::Varint)?;
        }
        out.extend_from_slice(&self.data);
        if self.open {
            crate::bytes::encode(&mut out, &self.protocol_id, MAX_PROTOCOL_ID_LEN)
                .map_err(|_| FrameError::LengthExceedsLimit)?;
            crate::bytes::encode(&mut out, &self.metadata, MAX_STREAM_METADATA_LEN)
                .map_err(|_| FrameError::LengthExceedsLimit)?;
        }
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let stream_id = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xE0 != 0 {
            return Err(FrameError::InvalidPadding); // reserved bits nonzero
        }
        let offset_present = flags & 0x02 != 0;
        let len_present = flags & 0x04 != 0;
        let offset = if offset_present { read_varint(&mut pos)? } else { 0 };
        let data_len = if len_present {
            let l = read_varint(&mut pos)?;
            if l > u32::MAX as u64 { return Err(FrameError::LengthExceedsLimit); }
            l as usize
        } else {
            body.len() - pos
        };
        let end = pos.checked_add(data_len).ok_or(FrameError::Truncated)?;
        let data = body.get(pos..end).ok_or(FrameError::Truncated)?.to_vec();
        pos = end;
        let mut protocol_id = Vec::new();
        let mut metadata = Vec::new();
        if flags & 0x08 != 0 {
            let (v, n) = crate::bytes::decode(&body[pos..], MAX_PROTOCOL_ID_LEN).map_err(|_| FrameError::Truncated)?;
            protocol_id = v.to_vec();
            pos += n;
            let (v, n) = crate::bytes::decode(&body[pos..], MAX_STREAM_METADATA_LEN).map_err(|_| FrameError::Truncated)?;
            metadata = v.to_vec();
            pos += n;
        }
        Ok((
            Self {
                stream_id,
                fin: flags & 0x01 != 0,
                offset_present,
                len_present,
                open: flags & 0x08 != 0,
                unidirectional: flags & 0x10 != 0,
                offset,
                data,
                protocol_id,
                metadata,
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetStreamFrame {
    pub stream_id: u64,
    pub app_error_code: u64,
    pub final_size: u64,
}

impl ResetStreamFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RESET_STREAM.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.stream_id).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.app_error_code).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.final_size).map_err(FrameError::Varint)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let stream_id = read_varint(&mut pos)?;
        let code = read_varint(&mut pos)?;
        let final_size = read_varint(&mut pos)?;
        Ok((Self { stream_id, app_error_code: code, final_size }, pos))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopSendingFrame {
    pub stream_id: u64,
    pub app_error_code: u64,
}

impl StopSendingFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::STOP_SENDING.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.stream_id).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.app_error_code).map_err(FrameError::Varint)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let stream_id = read_varint(&mut pos)?;
        let code = read_varint(&mut pos)?;
        Ok((Self { stream_id, app_error_code: code }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_round_trip_with_open() {
        let f = StreamFrame {
            stream_id: 0,
            fin: true,
            offset_present: true,
            len_present: true,
            open: true,
            unidirectional: false,
            offset: 0,
            data: b"hello".to_vec(),
            protocol_id: b"org.example.echo/1".to_vec(),
            metadata: Vec::new(),
        };
        let enc = f.encode().unwrap();
        let (dec, used) = StreamFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn stream_data_to_end_of_packet() {
        // LEN_PRESENT = 0: data extends to packet end.
        let enc = [0x10, 0x00, 0x00, 0x61, 0x62, 0x63];
        let (dec, used) = StreamFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec.data, b"abc");
        assert_eq!(used, enc.len() - 1);
        assert!(!dec.len_present);
    }

    #[test]
    fn reset_stream_round_trip() {
        let f = ResetStreamFrame { stream_id: 4, app_error_code: 7, final_size: 100 };
        let enc = f.encode().unwrap();
        let (dec, _) = ResetStreamFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn stop_sending_round_trip() {
        let f = StopSendingFrame { stream_id: 5, app_error_code: 1 };
        let enc = f.encode().unwrap();
        let (dec, _) = StopSendingFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }
}
```

- [ ] **Step 2: Add to frames/mod.rs and dispatch**

Append to `frames/mod.rs`:

```rust
pub mod simple;
pub mod stream;
```

In `frame.rs` `decode_frames`, add arms before the fallback:

```rust
                    FrameType::STREAM => {
                        let (f, used) = crate::frames::stream::StreamFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::Stream(f));
                    }
                    FrameType::RESET_STREAM => {
                        let (f, used) = crate::frames::stream::ResetStreamFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::ResetStream(f));
                    }
                    FrameType::STOP_SENDING => {
                        let (f, used) = crate::frames::stream::StopSendingFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::StopSending(f));
                    }
```

and extend the `Frame` enum:

```rust
    Stream(crate::frames::stream::StreamFrame),
    ResetStream(crate::frames::stream::ResetStreamFrame),
    StopSending(crate::frames::stream::StopSendingFrame),
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-wire`
Expected: PASS (11 frame tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/src/frame.rs crates/umc-wire/src/frames
git commit -m "feat(wire): STREAM, RESET_STREAM, STOP_SENDING frames"
```

### Task 10: Flow-control and datagram frames

**Files:**
- Create: `crates/umc-wire/src/frames/flow.rs`
- Create: `crates/umc-wire/src/frames/datagram.rs`

- [ ] **Step 1: Write flow-control frames**

`crates/umc-wire/src/frames/flow.rs`:

```rust
use crate::frame::FrameError;
use umc_types::frame::FrameType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxDataFrame {
    pub maximum_data: u64,
}

impl MaxDataFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::MAX_DATA.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.maximum_data).map_err(FrameError::Varint)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (v, n) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        Ok((Self { maximum_data: v }, n))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxStreamDataFrame {
    pub stream_id: u64,
    pub maximum_stream_data: u64,
}

impl MaxStreamDataFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::MAX_STREAM_DATA.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.stream_id).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.maximum_stream_data).map_err(FrameError::Varint)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (sid, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        let (max, n2) = crate::varint::decode(&body[n1..]).map_err(FrameError::Varint)?;
        Ok((Self { stream_id: sid, maximum_stream_data: max }, n1 + n2))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxStreamsFrame {
    pub bidirectional: bool,
    pub maximum_streams: u64,
}

impl MaxStreamsFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::MAX_STREAMS.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, u64::from(!self.bidirectional)).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.maximum_streams).map_err(FrameError::Varint)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (dir, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        if dir > 1 {
            return Err(FrameError::InvalidPadding);
        }
        let (max, n2) = crate::varint::decode(&body[n1..]).map_err(FrameError::Varint)?;
        Ok((Self { bidirectional: dir == 0, maximum_streams: max }, n1 + n2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_data_round_trip() {
        let f = MaxDataFrame { maximum_data: 4 * 1024 * 1024 };
        let enc = f.encode().unwrap();
        let (dec, _) = MaxDataFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn max_stream_data_round_trip() {
        let f = MaxStreamDataFrame { stream_id: 3, maximum_stream_data: 256 * 1024 };
        let enc = f.encode().unwrap();
        let (dec, _) = MaxStreamDataFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn max_streams_round_trip_and_direction_validation() {
        let f = MaxStreamsFrame { bidirectional: true, maximum_streams: 16 };
        let enc = f.encode().unwrap();
        let (dec, _) = MaxStreamsFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(MaxStreamsFrame::decode(&[0x02, 0x10]).unwrap_err(), FrameError::InvalidPadding);
    }
}
```

- [ ] **Step 2: Write the datagram frame**

`crates/umc-wire/src/frames/datagram.rs`:

```rust
use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_DATAGRAM_PAYLOAD: usize = 1_200; // initial path-safe bound

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramFrame {
    pub context_id: u64,
    pub ack_requested: bool,
    pub duplicate_suppression: bool,
    pub expiration_delta: Option<u64>,
    pub data: Vec<u8>,
}

impl DatagramFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.data.len() > MAX_DATAGRAM_PAYLOAD {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::DATAGRAM.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.context_id).map_err(FrameError::Varint)?;
        let mut flags = 0u8;
        if self.ack_requested { flags |= 0x01; }
        if self.duplicate_suppression { flags |= 0x02; }
        if self.expiration_delta.is_some() { flags |= 0x04; }
        out.push(flags);
        if let Some(d) = self.expiration_delta {
            crate::varint::encode_into(&mut out, d).map_err(FrameError::Varint)?;
        }
        crate::varint::encode_into(&mut out, self.data.len() as u64).map_err(FrameError::Varint)?;
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let context_id = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xF8 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let expiration_delta = if flags & 0x04 != 0 { Some(read_varint(&mut pos)?) } else { None };
        let data_len = read_varint(&mut pos)?;
        if data_len > MAX_DATAGRAM_PAYLOAD as u64 {
            return Err(FrameError::LengthExceedsLimit);
        }
        let end = pos.checked_add(data_len as usize).ok_or(FrameError::Truncated)?;
        let data = body.get(pos..end).ok_or(FrameError::Truncated)?.to_vec();
        Ok((
            Self {
                context_id,
                ack_requested: flags & 0x01 != 0,
                duplicate_suppression: flags & 0x02 != 0,
                expiration_delta,
                data,
            },
            end,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_round_trip_with_expiration() {
        let f = DatagramFrame {
            context_id: 7,
            ack_requested: true,
            duplicate_suppression: false,
            expiration_delta: Some(500),
            data: b"ping".to_vec(),
        };
        let enc = f.encode().unwrap();
        let (dec, used) = DatagramFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn rejects_oversize_datagram() {
        let f = DatagramFrame {
            context_id: 0,
            ack_requested: false,
            duplicate_suppression: false,
            expiration_delta: None,
            data: vec![0u8; MAX_DATAGRAM_PAYLOAD + 1],
        };
        assert_eq!(f.encode(), Err(FrameError::LengthExceedsLimit));
    }
}
```

- [ ] **Step 3: Wire into dispatch**

Append to `frames/mod.rs`: `pub mod datagram; pub mod flow;`

In `frame.rs`:

```rust
    MaxData(crate::frames::flow::MaxDataFrame),
    MaxStreamData(crate::frames::flow::MaxStreamDataFrame),
    MaxStreams(crate::frames::flow::MaxStreamsFrame),
    Datagram(crate::frames::datagram::DatagramFrame),
```

and dispatch arms:

```rust
                    FrameType::MAX_DATA => {
                        let (f, used) = crate::frames::flow::MaxDataFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::MaxData(f));
                    }
                    FrameType::MAX_STREAM_DATA => {
                        let (f, used) = crate::frames::flow::MaxStreamDataFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::MaxStreamData(f));
                    }
                    FrameType::MAX_STREAMS => {
                        let (f, used) = crate::frames::flow::MaxStreamsFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::MaxStreams(f));
                    }
                    FrameType::DATAGRAM => {
                        let (f, used) = crate::frames::datagram::DatagramFrame::decode(rest)?;
                        pos += used;
                        out.push(Frame::Datagram(f));
                    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-wire`
Expected: PASS (16 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-wire/src/frame.rs crates/umc-wire/src/frames
git commit -m "feat(wire): flow-control and DATAGRAM frames"
```

---

### Task 11: Path-management frames

**Files:**
- Create: `crates/umc-wire/src/frames/path.rs`

- [ ] **Step 1: Write path frames with tests**

`crates/umc-wire/src/frames/path.rs`:

```rust
use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const CHALLENGE_LEN: usize = 8;
pub const RESET_TOKEN_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChallengeFrame {
    pub data: [u8; CHALLENGE_LEN],
}

impl PathChallengeFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::PATH_CHALLENGE.0).map_err(FrameError::Varint)?;
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut data = [0u8; CHALLENGE_LEN];
        data.copy_from_slice(body.get(..CHALLENGE_LEN).ok_or(FrameError::Truncated)?);
        Ok((Self { data }, CHALLENGE_LEN))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathResponseFrame {
    pub data: [u8; CHALLENGE_LEN],
}

impl PathResponseFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::PATH_RESPONSE.0).map_err(FrameError::Varint)?;
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut data = [0u8; CHALLENGE_LEN];
        data.copy_from_slice(body.get(..CHALLENGE_LEN).ok_or(FrameError::Truncated)?);
        Ok((Self { data }, CHALLENGE_LEN))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathStatusFrame {
    pub path_id: u64,
    pub validated: bool,
    pub active: bool,
    pub degraded: bool,
    pub local: bool,
    pub metered: bool,
    pub censored_or_filtered: bool,
    pub estimated_rtt: u64,
    pub estimated_bandwidth: u64,
    pub estimated_loss: u64,
    pub cost_class: u64,
}

impl PathStatusFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::PATH_STATUS.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.path_id).map_err(FrameError::Varint)?;
        let mut flags = 0u8;
        if self.validated { flags |= 0x01; }
        if self.active { flags |= 0x02; }
        if self.degraded { flags |= 0x04; }
        if self.local { flags |= 0x08; }
        if self.metered { flags |= 0x10; }
        if self.censored_or_filtered { flags |= 0x20; }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.estimated_rtt).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.estimated_bandwidth).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.estimated_loss).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.cost_class).map_err(FrameError::Varint)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let path_id = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xC0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let rtt = read_varint(&mut pos)?;
        let bw = read_varint(&mut pos)?;
        let loss = read_varint(&mut pos)?;
        let cost = read_varint(&mut pos)?;
        Ok((
            Self {
                path_id,
                validated: flags & 0x01 != 0,
                active: flags & 0x02 != 0,
                degraded: flags & 0x04 != 0,
                local: flags & 0x08 != 0,
                metered: flags & 0x10 != 0,
                censored_or_filtered: flags & 0x20 != 0,
                estimated_rtt: rtt,
                estimated_bandwidth: bw,
                estimated_loss: loss,
                cost_class: cost,
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateFrame {
    pub old_path_id: u64,
    pub new_path_id: u64,
    pub migration_sequence: u64,
    pub make_primary: bool,
    pub keep_old_path: bool,
    pub duplicate_critical_frames: bool,
}

impl MigrateFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::MIGRATE.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.old_path_id).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.new_path_id).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.migration_sequence).map_err(FrameError::Varint)?;
        let mut flags = 0u8;
        if self.make_primary { flags |= 0x01; }
        if self.keep_old_path { flags |= 0x02; }
        if self.duplicate_critical_frames { flags |= 0x04; }
        out.push(flags);
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let old = read_varint(&mut pos)?;
        let new = read_varint(&mut pos)?;
        let seq = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xF8 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        Ok((
            Self {
                old_path_id: old,
                new_path_id: new,
                migration_sequence: seq,
                make_primary: flags & 0x01 != 0,
                keep_old_path: flags & 0x02 != 0,
                duplicate_critical_frames: flags & 0x04 != 0,
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUpdateFrame {
    pub update_sequence: u64,
    pub request_peer_update: bool,
}

impl KeyUpdateFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::KEY_UPDATE.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.update_sequence).map_err(FrameError::Varint)?;
        out.push(u8::from(self.request_peer_update));
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (seq, n) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        let flags = *body.get(n).ok_or(FrameError::Truncated)?;
        if flags & 0xFE != 0 {
            return Err(FrameError::InvalidPadding);
        }
        Ok((Self { update_sequence: seq, request_peer_update: flags & 0x01 != 0 }, n + 1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewConnectionIdFrame {
    pub sequence: u64,
    pub retire_prior_to: u64,
    pub connection_id: Vec<u8>,
    pub reset_token: [u8; RESET_TOKEN_LEN],
}

impl NewConnectionIdFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if !(1..=20).contains(&self.connection_id.len()) {
            return Err(FrameError::LengthExceedsLimit);
        }
        if self.retire_prior_to > self.sequence {
            return Err(FrameError::InvalidPadding);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::NEW_CONNECTION_ID.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.sequence).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.retire_prior_to).map_err(FrameError::Varint)?;
        out.push(self.connection_id.len() as u8);
        out.extend_from_slice(&self.connection_id);
        out.extend_from_slice(&self.reset_token);
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (seq, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        let (retire, n2) = crate::varint::decode(&body[n1..]).map_err(FrameError::Varint)?;
        let len_pos = n1 + n2;
        let cid_len = *body.get(len_pos).ok_or(FrameError::Truncated)? as usize;
        if !(1..=20).contains(&cid_len) {
            return Err(FrameError::LengthExceedsLimit);
        }
        let cid_start = len_pos + 1;
        let cid_end = cid_start.checked_add(cid_len).ok_or(FrameError::Truncated)?;
        let cid = body.get(cid_start..cid_end).ok_or(FrameError::Truncated)?.to_vec();
        let token_start = cid_end;
        let token_end = token_start.checked_add(RESET_TOKEN_LEN).ok_or(FrameError::Truncated)?;
        let mut reset_token = [0u8; RESET_TOKEN_LEN];
        reset_token.copy_from_slice(body.get(token_start..token_end).ok_or(FrameError::Truncated)?);
        if retire > seq {
            return Err(FrameError::InvalidPadding);
        }
        Ok((Self { sequence: seq, retire_prior_to: retire, connection_id: cid, reset_token }, token_end))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireConnectionIdFrame {
    pub sequence: u64,
}

impl RetireConnectionIdFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RETIRE_CONNECTION_ID.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.sequence).map_err(FrameError::Varint)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (seq, n) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        Ok((Self { sequence: seq }, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_challenge_round_trip() {
        let f = PathChallengeFrame { data: [7u8; CHALLENGE_LEN] };
        let enc = f.encode().unwrap();
        let (dec, used) = PathChallengeFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, CHALLENGE_LEN);
    }

    #[test]
    fn path_status_round_trip() {
        let f = PathStatusFrame {
            path_id: 1,
            validated: true,
            active: true,
            degraded: false,
            local: true,
            metered: false,
            censored_or_filtered: false,
            estimated_rtt: 25,
            estimated_bandwidth: 10_000,
            estimated_loss: 1,
            cost_class: 0,
        };
        let enc = f.encode().unwrap();
        let (dec, _) = PathStatusFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn migrate_round_trip() {
        let f = MigrateFrame { old_path_id: 0, new_path_id: 1, migration_sequence: 3, make_primary: true, keep_old_path: true, duplicate_critical_frames: false };
        let enc = f.encode().unwrap();
        let (dec, _) = MigrateFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn key_update_round_trip() {
        let f = KeyUpdateFrame { update_sequence: 1, request_peer_update: true };
        let enc = f.encode().unwrap();
        let (dec, _) = KeyUpdateFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn new_connection_id_round_trip_and_validation() {
        let f = NewConnectionIdFrame { sequence: 0, retire_prior_to: 0, connection_id: vec![1, 2, 3, 4, 5, 6, 7, 8], reset_token: [9u8; RESET_TOKEN_LEN] };
        let enc = f.encode().unwrap();
        let (dec, used) = NewConnectionIdFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
        let bad = NewConnectionIdFrame { sequence: 1, retire_prior_to: 2, connection_id: vec![1], reset_token: [0u8; 16] };
        assert_eq!(bad.encode(), Err(FrameError::InvalidPadding));
    }

    #[test]
    fn retire_connection_id_round_trip() {
        let f = RetireConnectionIdFrame { sequence: 2 };
        let enc = f.encode().unwrap();
        let (dec, _) = RetireConnectionIdFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }
}
```

- [ ] **Step 2: Wire into dispatch**

Append `pub mod path;` to `frames/mod.rs`; extend `Frame` enum and `decode_frames` with arms for `PATH_CHALLENGE`, `PATH_RESPONSE`, `PATH_STATUS`, `MIGRATE`, `KEY_UPDATE`, `NEW_CONNECTION_ID`, `RETIRE_CONNECTION_ID` following the exact pattern from Task 9.

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-wire`
Expected: PASS (22 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/src/frame.rs crates/umc-wire/src/frames
git commit -m "feat(wire): path-management frames"
```

---

### Task 12: Handshake-context frames

**Files:**
- Create: `crates/umc-wire/src/frames/handshake.rs`

- [ ] **Step 1: Write AUTH, HANDSHAKE_DATA, CAPABILITIES, SESSION_TICKET**

`crates/umc-wire/src/frames/handshake.rs`:

```rust
use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_HANDSHAKE_TRANSCRIPT: usize = 65_536;
pub const MAX_HANDSHAKE_MESSAGE: usize = 16_384;
pub const MAX_CAPABILITIES: usize = 128;
pub const MAX_CAPABILITY_VALUE: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFrame {
    pub method: u64,
    pub data: Vec<u8>,
}

impl AuthFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.data.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::AUTH.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.method).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.data, MAX_HANDSHAKE_MESSAGE).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (method, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        let (data, n2) = crate::bytes::decode(&body[n1..], MAX_HANDSHAKE_MESSAGE).map_err(|_| FrameError::Truncated)?;
        Ok((Self { method, data: data.to_vec() }, n1 + n2))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeDataFrame {
    pub offset: u64,
    pub data: Vec<u8>,
}

impl HandshakeDataFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.data.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::HANDSHAKE_DATA.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.offset).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.data, MAX_HANDSHAKE_MESSAGE).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (offset, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        let (data, n2) = crate::bytes::decode(&body[n1..], MAX_HANDSHAKE_MESSAGE).map_err(|_| FrameError::Truncated)?;
        Ok((Self { offset, data: data.to_vec() }, n1 + n2))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub id: u64,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesFrame {
    pub entries: Vec<Capability>,
}

impl CapabilitiesFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.entries.len() > MAX_CAPABILITIES {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::CAPABILITIES.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.entries.len() as u64).map_err(FrameError::Varint)?;
        for e in &self.entries {
            crate::varint::encode_into(&mut out, e.id).map_err(FrameError::Varint)?;
            crate::bytes::encode(&mut out, &e.value, MAX_CAPABILITY_VALUE).map_err(|_| FrameError::LengthExceedsLimit)?;
        }
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (count, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        if count as usize > MAX_CAPABILITIES {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut pos = n1;
        let mut entries = Vec::new();
        for _ in 0..count {
            let (id, n) = crate::varint::decode(&body[pos..]).map_err(FrameError::Varint)?;
            pos += n;
            let (value, n) = crate::bytes::decode(&body[pos..], MAX_CAPABILITY_VALUE).map_err(|_| FrameError::Truncated)?;
            pos += n;
            entries.push(Capability { id, value: value.to_vec() });
        }
        Ok((Self { entries }, pos))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTicketFrame {
    pub lifetime: u64,
    pub age_add: u64,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
}

impl SessionTicketFrame {
    pub const MAX_TICKET: usize = 16_384;

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::SESSION_TICKET.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.lifetime).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.age_add).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.nonce, 256).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.ticket, Self::MAX_TICKET).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let lifetime = read_varint(&mut pos)?;
        let age_add = read_varint(&mut pos)?;
        let (nonce, n) = crate::bytes::decode(&body[pos..], 256).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (ticket, n) = crate::bytes::decode(&body[pos..], Self::MAX_TICKET).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((Self { lifetime, age_add, nonce: nonce.to_vec(), ticket: ticket.to_vec() }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_round_trip() {
        let f = AuthFrame { method: 1, data: b"invitation-proof".to_vec() };
        let enc = f.encode().unwrap();
        let (dec, _) = AuthFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn handshake_data_round_trip() {
        let f = HandshakeDataFrame { offset: 0, data: b"client hello bytes".to_vec() };
        let enc = f.encode().unwrap();
        let (dec, _) = HandshakeDataFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn capabilities_round_trip() {
        let f = CapabilitiesFrame { entries: vec![Capability { id: 1, value: b"1200".to_vec() }] };
        let enc = f.encode().unwrap();
        let (dec, _) = CapabilitiesFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn session_ticket_round_trip() {
        let f = SessionTicketFrame { lifetime: 86_400, age_add: 7, nonce: vec![1, 2, 3], ticket: vec![9; 64] };
        let enc = f.encode().unwrap();
        let (dec, _) = SessionTicketFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }
}
```

- [ ] **Step 2: Wire into dispatch**

Append `pub mod handshake;` to `frames/mod.rs`; extend `Frame` enum and dispatch arms for `AUTH`, `HANDSHAKE_DATA`, `CAPABILITIES`, `SESSION_TICKET` following the established pattern.

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-wire`
Expected: PASS (26 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/src/frame.rs crates/umc-wire/src/frames
git commit -m "feat(wire): handshake-context frames"
```

---

### Task 13: Routing and relay frames

**Files:**
- Create: `crates/umc-wire/src/frames/routing.rs`
- Create: `crates/umc-wire/src/frames/relay.rs`

- [ ] **Step 1: Write routing frames**

`crates/umc-wire/src/frames/routing.rs`:

```rust
use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_HOP_LIMIT: u64 = 32;
pub const MAX_DESTINATION_HINT: usize = 512;
pub const MAX_PATH_EXCLUSIONS: usize = 32;
pub const MAX_ROUTE_AUTH: usize = 1_024;
pub const MAX_EXCLUSION_ENTRY: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRequestFrame {
    pub request_id: u64,
    pub allow_relay: bool,
    pub allow_store_forward: bool,
    pub require_private_response: bool,
    pub local_scope_only: bool,
    pub gateway_query: bool,
    pub hop_limit: u64,
    pub expiration_delta: u64,
    pub destination_hint: Vec<u8>,
    pub path_exclusions: Vec<Vec<u8>>,
    pub requester_auth: Vec<u8>,
}

impl RouteRequestFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.hop_limit == 0 || self.hop_limit > MAX_HOP_LIMIT {
            return Err(FrameError::InvalidPadding);
        }
        if self.path_exclusions.len() > MAX_PATH_EXCLUSIONS {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::ROUTE_REQUEST.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.request_id).map_err(FrameError::Varint)?;
        let mut flags = 0u8;
        if self.allow_relay { flags |= 0x01; }
        if self.allow_store_forward { flags |= 0x02; }
        if self.require_private_response { flags |= 0x04; }
        if self.local_scope_only { flags |= 0x08; }
        if self.gateway_query { flags |= 0x10; }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.hop_limit).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.expiration_delta).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.destination_hint, MAX_DESTINATION_HINT).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::varint::encode_into(&mut out, self.path_exclusions.len() as u64).map_err(FrameError::Varint)?;
        for e in &self.path_exclusions {
            crate::bytes::encode(&mut out, e, MAX_EXCLUSION_ENTRY).map_err(|_| FrameError::LengthExceedsLimit)?;
        }
        crate::bytes::encode(&mut out, &self.requester_auth, MAX_ROUTE_AUTH).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let request_id = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xE0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let hop_limit = read_varint(&mut pos)?;
        if hop_limit == 0 || hop_limit > MAX_HOP_LIMIT {
            return Err(FrameError::InvalidPadding);
        }
        let expiration = read_varint(&mut pos)?;
        let (hint, n) = crate::bytes::decode(&body[pos..], MAX_DESTINATION_HINT).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let ex_count = read_varint(&mut pos)?;
        if ex_count as usize > MAX_PATH_EXCLUSIONS {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut exclusions = Vec::new();
        for _ in 0..ex_count {
            let (e, n) = crate::bytes::decode(&body[pos..], MAX_EXCLUSION_ENTRY).map_err(|_| FrameError::Truncated)?;
            pos += n;
            exclusions.push(e.to_vec());
        }
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_ROUTE_AUTH).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                request_id,
                allow_relay: flags & 0x01 != 0,
                allow_store_forward: flags & 0x02 != 0,
                require_private_response: flags & 0x04 != 0,
                local_scope_only: flags & 0x08 != 0,
                gateway_query: flags & 0x10 != 0,
                hop_limit,
                expiration_delta: expiration,
                destination_hint: hint.to_vec(),
                path_exclusions: exclusions,
                requester_auth: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteResponseFrame {
    pub request_id: u64,
    pub response_sequence: u64,
    pub direct: bool,
    pub relay_required: bool,
    pub store_forward_available: bool,
    pub local_path: bool,
    pub gateway_path: bool,
    pub route_lifetime: u64,
    pub next_hop_hint: Vec<u8>,
    pub route_metadata: Vec<u8>,
    pub authentication: Vec<u8>,
}

impl RouteResponseFrame {
    pub const MAX_NEXT_HOP_HINT: usize = 1_024;
    pub const MAX_ROUTE_METADATA: usize = 4_096;

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.direct && self.relay_required {
            return Err(FrameError::InvalidPadding);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::ROUTE_RESPONSE.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.request_id).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.response_sequence).map_err(FrameError::Varint)?;
        let mut flags = 0u8;
        if self.direct { flags |= 0x01; }
        if self.relay_required { flags |= 0x02; }
        if self.store_forward_available { flags |= 0x04; }
        if self.local_path { flags |= 0x08; }
        if self.gateway_path { flags |= 0x10; }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.route_lifetime).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.next_hop_hint, Self::MAX_NEXT_HOP_HINT).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.route_metadata, Self::MAX_ROUTE_METADATA).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.authentication, MAX_ROUTE_AUTH).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let request_id = read_varint(&mut pos)?;
        let sequence = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xE0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let lifetime = read_varint(&mut pos)?;
        let (nh, n) = crate::bytes::decode(&body[pos..], Self::MAX_NEXT_HOP_HINT).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (meta, n) = crate::bytes::decode(&body[pos..], Self::MAX_ROUTE_METADATA).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_ROUTE_AUTH).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                request_id,
                response_sequence: sequence,
                direct: flags & 0x01 != 0,
                relay_required: flags & 0x02 != 0,
                store_forward_available: flags & 0x04 != 0,
                local_path: flags & 0x08 != 0,
                gateway_path: flags & 0x10 != 0,
                route_lifetime: lifetime,
                next_hop_hint: nh.to_vec(),
                route_metadata: meta.to_vec(),
                authentication: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteErrorFrame {
    pub request_id: u64,
    pub error_code: u64,
    pub failed_hop_index: u64,
    pub diagnostic: Vec<u8>,
}

impl RouteErrorFrame {
    pub const UNKNOWN_HOP: u64 = u64::MAX;
    pub const MAX_DIAGNOSTIC: usize = 256;

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::ROUTE_ERROR.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.request_id).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.error_code).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.failed_hop_index).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.diagnostic, Self::MAX_DIAGNOSTIC).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let request_id = read_varint(&mut pos)?;
        let code = read_varint(&mut pos)?;
        let hop = read_varint(&mut pos)?;
        let (diag, n) = crate::bytes::decode(&body[pos..], Self::MAX_DIAGNOSTIC).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((Self { request_id, error_code: code, failed_hop_index: hop, diagnostic: diag.to_vec() }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_request_round_trip() {
        let f = RouteRequestFrame {
            request_id: 99,
            allow_relay: true,
            allow_store_forward: false,
            require_private_response: true,
            local_scope_only: false,
            gateway_query: false,
            hop_limit: 8,
            expiration_delta: 30_000,
            destination_hint: b"token".to_vec(),
            path_exclusions: vec![b"relay-a".to_vec()],
            requester_auth: b"proof".to_vec(),
        };
        let enc = f.encode().unwrap();
        let (dec, used) = RouteRequestFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn route_request_rejects_bad_hop_limit() {
        let mut f = RouteRequestFrame { request_id: 1, allow_relay: false, allow_store_forward: false, require_private_response: false, local_scope_only: false, gateway_query: false, hop_limit: 33, expiration_delta: 100, destination_hint: vec![], path_exclusions: vec![], requester_auth: vec![] };
        assert_eq!(f.encode(), Err(FrameError::InvalidPadding));
        f.hop_limit = 0;
        assert_eq!(f.encode(), Err(FrameError::InvalidPadding));
    }

    #[test]
    fn route_response_rejects_direct_and_relay() {
        let f = RouteResponseFrame { request_id: 1, response_sequence: 0, direct: true, relay_required: true, store_forward_available: false, local_path: false, gateway_path: false, route_lifetime: 600, next_hop_hint: vec![], route_metadata: vec![], authentication: vec![] };
        assert_eq!(f.encode(), Err(FrameError::InvalidPadding));
    }

    #[test]
    fn route_error_round_trip() {
        let f = RouteErrorFrame { request_id: 2, error_code: 0x0D, failed_hop_index: RouteErrorFrame::UNKNOWN_HOP, diagnostic: vec![] };
        let enc = f.encode().unwrap();
        let (dec, _) = RouteErrorFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }
}
```

- [ ] **Step 2: Write relay frames**

`crates/umc-wire/src/frames/relay.rs`:

```rust
use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_RELAY_PAYLOAD: usize = 64 * 1024;
pub const MAX_RELAY_DIAGNOSTIC: usize = 256;
pub const MAX_RELAY_AUTH: usize = 1_024;
pub const MAX_REQUESTED_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOpenFrame {
    pub circuit_id: u64,
    pub bidirectional: bool,
    pub store_forward_allowed: bool,
    pub private_circuit: bool,
    pub multipath_allowed: bool,
    pub requested_lifetime: u64,
    pub requested_byte_quota: u64,
    pub next_hop_hint: Vec<u8>,
    pub authorization: Vec<u8>,
}

impl RelayOpenFrame {
    pub const MAX_NEXT_HOP_HINT: usize = 1_024;

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.requested_lifetime != 0 && (self.requested_lifetime < 1_000 || self.requested_lifetime > MAX_REQUESTED_LIFETIME_MS) {
            return Err(FrameError::InvalidPadding);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RELAY_OPEN.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.circuit_id).map_err(FrameError::Varint)?;
        let mut flags = 0u8;
        if self.bidirectional { flags |= 0x01; }
        if self.store_forward_allowed { flags |= 0x02; }
        if self.private_circuit { flags |= 0x04; }
        if self.multipath_allowed { flags |= 0x08; }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.requested_lifetime).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.requested_byte_quota).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.next_hop_hint, Self::MAX_NEXT_HOP_HINT).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.authorization, MAX_RELAY_AUTH).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let circuit_id = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xF0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let lifetime = read_varint(&mut pos)?;
        if lifetime != 0 && (lifetime < 1_000 || lifetime > MAX_REQUESTED_LIFETIME_MS) {
            return Err(FrameError::InvalidPadding);
        }
        let quota = read_varint(&mut pos)?;
        let (nh, n) = crate::bytes::decode(&body[pos..], Self::MAX_NEXT_HOP_HINT).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_RELAY_AUTH).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                circuit_id,
                bidirectional: flags & 0x01 != 0,
                store_forward_allowed: flags & 0x02 != 0,
                private_circuit: flags & 0x04 != 0,
                multipath_allowed: flags & 0x08 != 0,
                requested_lifetime: lifetime,
                requested_byte_quota: quota,
                next_hop_hint: nh.to_vec(),
                authorization: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStatusFrame {
    pub circuit_id: u64,
    pub status_sequence: u64,
    pub status_code: u64,
    pub bidirectional_granted: bool,
    pub private_handling_granted: bool,
    pub multipath_granted: bool,
    pub downstream_authenticated: bool,
    pub retryable: bool,
    pub granted_lifetime: u64,
    pub granted_byte_quota: u64,
    pub maximum_relay_payload: u64,
    pub diagnostic: Vec<u8>,
    pub authentication: Vec<u8>,
}

impl RelayStatusFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RELAY_STATUS.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.circuit_id).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.status_sequence).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.status_code).map_err(FrameError::Varint)?;
        let mut flags = 0u8;
        if self.bidirectional_granted { flags |= 0x01; }
        if self.private_handling_granted { flags |= 0x02; }
        if self.multipath_granted { flags |= 0x04; }
        if self.downstream_authenticated { flags |= 0x08; }
        if self.retryable { flags |= 0x10; }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.granted_lifetime).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.granted_byte_quota).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.maximum_relay_payload).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.diagnostic, MAX_RELAY_DIAGNOSTIC).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.authentication, MAX_RELAY_AUTH).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let circuit_id = read_varint(&mut pos)?;
        let seq = read_varint(&mut pos)?;
        let code = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xE0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let lifetime = read_varint(&mut pos)?;
        let quota = read_varint(&mut pos)?;
        let max_payload = read_varint(&mut pos)?;
        let (diag, n) = crate::bytes::decode(&body[pos..], MAX_RELAY_DIAGNOSTIC).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_RELAY_AUTH).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                circuit_id,
                status_sequence: seq,
                status_code: code,
                bidirectional_granted: flags & 0x01 != 0,
                private_handling_granted: flags & 0x02 != 0,
                multipath_granted: flags & 0x04 != 0,
                downstream_authenticated: flags & 0x08 != 0,
                retryable: flags & 0x10 != 0,
                granted_lifetime: lifetime,
                granted_byte_quota: quota,
                maximum_relay_payload: max_payload,
                diagnostic: diag.to_vec(),
                authentication: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDataFrame {
    pub circuit_id: u64,
    pub relay_sequence: u64,
    pub fin: bool,
    pub ack_requested: bool,
    pub high_priority: bool,
    pub data: Vec<u8>,
}

impl RelayDataFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.data.len() > MAX_RELAY_PAYLOAD {
            return Err(FrameError::LengthExceedsLimit);
        }
        if self.data.is_empty() && !self.fin {
            return Err(FrameError::InvalidPadding);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RELAY_DATA.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.circuit_id).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.relay_sequence).map_err(FrameError::Varint)?;
        let mut flags = 0u8;
        if self.fin { flags |= 0x01; }
        if self.ack_requested { flags |= 0x02; }
        if self.high_priority { flags |= 0x04; }
        out.push(flags);
        crate::bytes::encode(&mut out, &self.data, MAX_RELAY_PAYLOAD).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let circuit_id = read_varint(&mut pos)?;
        let seq = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xF8 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let (data, n) = crate::bytes::decode(&body[pos..], MAX_RELAY_PAYLOAD).map_err(|_| FrameError::Truncated)?;
        pos += n;
        if data.is_empty() && flags & 0x01 == 0 {
            return Err(FrameError::InvalidPadding);
        }
        Ok((
            Self {
                circuit_id,
                relay_sequence: seq,
                fin: flags & 0x01 != 0,
                ack_requested: flags & 0x02 != 0,
                high_priority: flags & 0x04 != 0,
                data: data.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCloseFrame {
    pub circuit_id: u64,
    pub reason_code: u64,
    pub final_relay_sequence: u64,
}

impl RelayCloseFrame {
    pub const NO_SEQUENCE: u64 = u64::MAX;

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RELAY_CLOSE.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.circuit_id).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.reason_code).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.final_relay_sequence).map_err(FrameError::Varint)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let circuit_id = read_varint(&mut pos)?;
        let reason = read_varint(&mut pos)?;
        let final_seq = read_varint(&mut pos)?;
        Ok((Self { circuit_id, reason_code: reason, final_relay_sequence: final_seq }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_open_round_trip() {
        let f = RelayOpenFrame { circuit_id: 7, bidirectional: true, store_forward_allowed: false, private_circuit: true, multipath_allowed: false, requested_lifetime: 600_000, requested_byte_quota: 1_048_576, next_hop_hint: b"peer-candidate".to_vec(), authorization: b"proof".to_vec() };
        let enc = f.encode().unwrap();
        let (dec, used) = RelayOpenFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn relay_open_rejects_out_of_range_lifetime() {
        let mut f = RelayOpenFrame { circuit_id: 1, bidirectional: false, store_forward_allowed: false, private_circuit: false, multipath_allowed: false, requested_lifetime: 100, requested_byte_quota: 0, next_hop_hint: vec![], authorization: vec![] };
        assert_eq!(f.encode(), Err(FrameError::InvalidPadding));
        f.requested_lifetime = MAX_REQUESTED_LIFETIME_MS + 1;
        assert_eq!(f.encode(), Err(FrameError::InvalidPadding));
    }

    #[test]
    fn relay_status_round_trip() {
        let f = RelayStatusFrame { circuit_id: 3, status_sequence: 0, status_code: 1, bidirectional_granted: true, private_handling_granted: false, multipath_granted: false, downstream_authenticated: true, retryable: false, granted_lifetime: 600_000, granted_byte_quota: 1_048_576, maximum_relay_payload: 65_536, diagnostic: vec![], authentication: vec![] };
        let enc = f.encode().unwrap();
        let (dec, _) = RelayStatusFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn relay_data_round_trip_and_empty_rule() {
        let f = RelayDataFrame { circuit_id: 5, relay_sequence: 0, fin: false, ack_requested: true, high_priority: false, data: b"inner-packet".to_vec() };
        let enc = f.encode().unwrap();
        let (dec, _) = RelayDataFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        let empty = RelayDataFrame { circuit_id: 5, relay_sequence: 1, fin: false, ack_requested: false, high_priority: false, data: vec![] };
        assert_eq!(empty.encode(), Err(FrameError::InvalidPadding));
    }

    #[test]
    fn relay_close_round_trip() {
        let f = RelayCloseFrame { circuit_id: 9, reason_code: 6, final_relay_sequence: 100 };
        let enc = f.encode().unwrap();
        let (dec, _) = RelayCloseFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }
}
```

- [ ] **Step 3: Wire into dispatch**

Append `pub mod relay; pub mod routing;` to `frames/mod.rs`; extend `Frame` enum and dispatch arms for `ROUTE_REQUEST`, `ROUTE_RESPONSE`, `ROUTE_ERROR`, `RELAY_OPEN`, `RELAY_STATUS`, `RELAY_DATA`, `RELAY_CLOSE`.

The routing and relay frames are critical length-delimited. The dispatch arms must read the length prefix before calling decode:

```rust
                    FrameType::ROUTE_REQUEST => {
                        let (len, n) = crate::varint::decode(rest).map_err(FrameError::Varint)?;
                        let body = rest.get(n..n + len as usize).ok_or(FrameError::Truncated)?;
                        let (f, _) = crate::frames::routing::RouteRequestFrame::decode(body)?;
                        pos += n + len as usize;
                        out.push(Frame::RouteRequest(f));
                    }
```

Apply the same length-delimited pattern for `ROUTE_RESPONSE`, `ROUTE_ERROR`, `RELAY_OPEN`, `RELAY_STATUS`, `RELAY_CLOSE`. `RELAY_DATA` is fixed-layout and decodes directly from `rest` like the Task 9 pattern.

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-wire`
Expected: PASS (32 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-wire/src/frame.rs crates/umc-wire/src/frames
git commit -m "feat(wire): routing and relay frames"
```

---

### Task 14: Bundle, peer-hint, and service-hint frames

**Files:**
- Create: `crates/umc-wire/src/frames/bundle.rs`
- Create: `crates/umc-wire/src/frames/misc.rs`

- [ ] **Step 1: Write bundle frames**

`crates/umc-wire/src/frames/bundle.rs`:

```rust
use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_BUNDLE_ID: usize = 64;
pub const MAX_BUNDLE_DESTINATION_HINT: usize = 512;
pub const MAX_BUNDLE_AUTH: usize = 1_024;
pub const MAX_BUNDLE_PAYLOAD: usize = 65_535 - 128; // one base frame, headers/tags excluded

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFrame {
    pub bundle_id: Vec<u8>,
    pub custody_requested: bool,
    pub delivery_ack_requested: bool,
    pub do_not_replicate: bool,
    pub local_scope_only: bool,
    pub high_sensitivity: bool,
    pub priority: u64,
    pub creation_time: u64,
    pub expiration_time: u64,
    pub replication_limit: u64,
    pub destination_hint: Vec<u8>,
    pub payload: Vec<u8>,
    pub bundle_auth: Vec<u8>,
}

impl BundleFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_BUNDLE_PAYLOAD {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::BUNDLE.0).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.bundle_id, MAX_BUNDLE_ID).map_err(|_| FrameError::LengthExceedsLimit)?;
        let mut flags = 0u8;
        if self.custody_requested { flags |= 0x01; }
        if self.delivery_ack_requested { flags |= 0x02; }
        if self.do_not_replicate { flags |= 0x04; }
        if self.local_scope_only { flags |= 0x08; }
        if self.high_sensitivity { flags |= 0x10; }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.priority).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.creation_time).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.expiration_time).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.replication_limit).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.destination_hint, MAX_BUNDLE_DESTINATION_HINT).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.payload, MAX_BUNDLE_PAYLOAD).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.bundle_auth, MAX_BUNDLE_AUTH).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let mut read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let (id, n) = crate::bytes::decode(&body[pos..], MAX_BUNDLE_ID).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xE0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let priority = read_varint(&mut pos)?;
        let created = read_varint(&mut pos)?;
        let expires = read_varint(&mut pos)?;
        let replication = read_varint(&mut pos)?;
        let (dh, n) = crate::bytes::decode(&body[pos..], MAX_BUNDLE_DESTINATION_HINT).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (payload, n) = crate::bytes::decode(&body[pos..], MAX_BUNDLE_PAYLOAD).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_BUNDLE_AUTH).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                bundle_id: id.to_vec(),
                custody_requested: flags & 0x01 != 0,
                delivery_ack_requested: flags & 0x02 != 0,
                do_not_replicate: flags & 0x04 != 0,
                local_scope_only: flags & 0x08 != 0,
                high_sensitivity: flags & 0x10 != 0,
                priority,
                creation_time: created,
                expiration_time: expires,
                replication_limit: replication,
                destination_hint: dh.to_vec(),
                payload: payload.to_vec(),
                bundle_auth: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleAckFrame {
    pub bundle_id: Vec<u8>,
    pub status: u64,
    pub stored_until: u64,
    pub authentication: Vec<u8>,
}

impl BundleAckFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::BUNDLE_ACK.0).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.bundle_id, MAX_BUNDLE_ID).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::varint::encode_into(&mut out, self.status).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.stored_until).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.authentication, MAX_BUNDLE_AUTH).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let (id, n) = crate::bytes::decode(&body[pos..], MAX_BUNDLE_ID).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (status, n) = crate::varint::decode(&body[pos..]).map_err(FrameError::Varint)?;
        pos += n;
        let (stored_until, n) = crate::varint::decode(&body[pos..]).map_err(FrameError::Varint)?;
        pos += n;
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_BUNDLE_AUTH).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((Self { bundle_id: id.to_vec(), status, stored_until, authentication: auth.to_vec() }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_round_trip() {
        let f = BundleFrame {
            bundle_id: vec![1, 2, 3],
            custody_requested: false,
            delivery_ack_requested: true,
            do_not_replicate: true,
            local_scope_only: false,
            high_sensitivity: false,
            priority: 1,
            creation_time: 1_700_000_000_000,
            expiration_time: 1_700_086_400_000,
            replication_limit: 3,
            destination_hint: b"dest-token".to_vec(),
            payload: vec![0xAA; 256],
            bundle_auth: b"sig".to_vec(),
        };
        let enc = f.encode().unwrap();
        let (dec, used) = BundleFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn bundle_ack_round_trip() {
        let f = BundleAckFrame { bundle_id: vec![1, 2, 3], status: 1, stored_until: 1_700_086_400_000, authentication: vec![] };
        let enc = f.encode().unwrap();
        let (dec, _) = BundleAckFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }
}
```

- [ ] **Step 2: Write PEER_HINT and SERVICE_HINT**

`crates/umc-wire/src/frames/misc.rs`:

```rust
use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_HINTS: usize = 32;
pub const MAX_PEER_ID: usize = 64;
pub const MAX_CARRIER_TYPE: usize = 64;
pub const MAX_CONNECTION_HINT: usize = 1_024;
pub const MAX_AUTHENTICATOR: usize = 1_024;
pub const MAX_PROTOCOL_ID: usize = 255;
pub const MAX_SERVICE_METADATA: usize = 4_096;
pub const MAX_SIGNATURE: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHintEntry {
    pub temporary_peer_id: Vec<u8>,
    pub carrier_type: Vec<u8>,
    pub connection_hint: Vec<u8>,
    pub expiration_time: u64,
    pub public: bool,
    pub introduced: bool,
    pub local: bool,
    pub ephemeral: bool,
    pub do_not_reshare: bool,
    pub authenticator: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHintFrame {
    pub entries: Vec<PeerHintEntry>,
}

impl PeerHintFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.entries.len() > MAX_HINTS {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::PEER_HINT.0).map_err(FrameError::Varint)?;
        crate::varint::encode_into(&mut out, self.entries.len() as u64).map_err(FrameError::Varint)?;
        for e in &self.entries {
            crate::bytes::encode(&mut out, &e.temporary_peer_id, MAX_PEER_ID).map_err(|_| FrameError::LengthExceedsLimit)?;
            crate::bytes::encode(&mut out, &e.carrier_type, MAX_CARRIER_TYPE).map_err(|_| FrameError::LengthExceedsLimit)?;
            crate::bytes::encode(&mut out, &e.connection_hint, MAX_CONNECTION_HINT).map_err(|_| FrameError::LengthExceedsLimit)?;
            crate::varint::encode_into(&mut out, e.expiration_time).map_err(FrameError::Varint)?;
            let mut flags = 0u8;
            if e.public { flags |= 0x01; }
            if e.introduced { flags |= 0x02; }
            if e.local { flags |= 0x04; }
            if e.ephemeral { flags |= 0x08; }
            if e.do_not_reshare { flags |= 0x10; }
            out.push(flags);
            crate::bytes::encode(&mut out, &e.authenticator, MAX_AUTHENTICATOR).map_err(|_| FrameError::LengthExceedsLimit)?;
        }
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (count, mut pos) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        if count as usize > MAX_HINTS {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut entries = Vec::new();
        for _ in 0..count {
            let (v, n) = crate::bytes::decode(&body[pos..], MAX_PEER_ID).map_err(|_| FrameError::Truncated)?;
            let temp_peer_id = v.to_vec();
            pos += n;
            let (v, n) = crate::bytes::decode(&body[pos..], MAX_CARRIER_TYPE).map_err(|_| FrameError::Truncated)?;
            let carrier_type = v.to_vec();
            pos += n;
            let (v, n) = crate::bytes::decode(&body[pos..], MAX_CONNECTION_HINT).map_err(|_| FrameError::Truncated)?;
            let connection_hint = v.to_vec();
            pos += n;
            let (expiration, n) = crate::varint::decode(&body[pos..]).map_err(FrameError::Varint)?;
            pos += n;
            let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
            pos += 1;
            if flags & 0xE0 != 0 {
                return Err(FrameError::InvalidPadding);
            }
            let (auth, n) = crate::bytes::decode(&body[pos..], MAX_AUTHENTICATOR).map_err(|_| FrameError::Truncated)?;
            pos += n;
            entries.push(PeerHintEntry {
                temporary_peer_id: temp_peer_id,
                carrier_type,
                connection_hint,
                expiration_time: expiration,
                public: flags & 0x01 != 0,
                introduced: flags & 0x02 != 0,
                local: flags & 0x04 != 0,
                ephemeral: flags & 0x08 != 0,
                do_not_reshare: flags & 0x10 != 0,
                authenticator: auth.to_vec(),
            });
        }
        Ok((Self { entries }, pos))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHintFrame {
    pub protocol_id: Vec<u8>,
    pub endpoint_hint: Vec<u8>,
    pub metadata: Vec<u8>,
    pub expiration_time: u64,
    pub signature: Vec<u8>,
}

impl ServiceHintFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::SERVICE_HINT.0).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.protocol_id, MAX_PROTOCOL_ID).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.endpoint_hint, MAX_PEER_ID + MAX_CONNECTION_HINT).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.metadata, MAX_SERVICE_METADATA).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::varint::encode_into(&mut out, self.expiration_time).map_err(FrameError::Varint)?;
        crate::bytes::encode(&mut out, &self.signature, MAX_SIGNATURE).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let (protocol_id, n) = crate::bytes::decode(&body[pos..], MAX_PROTOCOL_ID).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (endpoint_hint, n) = crate::bytes::decode(&body[pos..], MAX_PEER_ID + MAX_CONNECTION_HINT).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (metadata, n) = crate::bytes::decode(&body[pos..], MAX_SERVICE_METADATA).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (expiration_time, n) = crate::varint::decode(&body[pos..]).map_err(FrameError::Varint)?;
        pos += n;
        let (signature, n) = crate::bytes::decode(&body[pos..], MAX_SIGNATURE).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((Self { protocol_id: protocol_id.to_vec(), endpoint_hint: endpoint_hint.to_vec(), metadata: metadata.to_vec(), expiration_time, signature: signature.to_vec() }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_hint_round_trip() {
        let f = PeerHintFrame { entries: vec![PeerHintEntry { temporary_peer_id: b"peer-1".to_vec(), carrier_type: b"ump.udp/1".to_vec(), connection_hint: b"1.2.3.4:5678".to_vec(), expiration_time: 1_700_000_000_000, public: true, introduced: false, local: false, ephemeral: false, do_not_reshare: false, authenticator: vec![] }] };
        let enc = f.encode().unwrap();
        let (dec, _) = PeerHintFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn service_hint_round_trip() {
        let f = ServiceHintFrame { protocol_id: b"org.example.echo/1".to_vec(), endpoint_hint: b"token".to_vec(), metadata: vec![], expiration_time: 1_700_000_000_000, signature: b"sig".to_vec() };
        let enc = f.encode().unwrap();
        let (dec, _) = ServiceHintFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }
}
```

- [ ] **Step 3: Wire into dispatch**

Append `pub mod bundle; pub mod misc;` to `frames/mod.rs`; extend `Frame` enum and dispatch arms for `BUNDLE`, `BUNDLE_ACK`, `PEER_HINT`, `SERVICE_HINT` using the length-delimited pattern from Task 13.

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-wire`
Expected: PASS (36 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-wire/src/frame.rs crates/umc-wire/src/frames
git commit -m "feat(wire): bundle, peer-hint, and service-hint frames"
```

---

### Task 15: Packet parser with frame-context validation

**Files:**
- Create: `crates/umc-wire/src/packet.rs`

- [ ] **Step 1: Write the failing packet-parser test**

`crates/umc-wire/src/packet.rs`:

```rust
use crate::frame::{decode_frames, Frame, FrameError};
use crate::header::{HeaderByte, LongPacketType, ShortPacketSpace};
use umc_types::version::MAX_PACKET_SIZE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketContext {
    Initial,
    Handshake,
    Protected(ShortPacketSpace),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    TooLarge,
    Frame(FrameError),
    ContextViolation(umc_types::frame::FrameType),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    pub context: PacketContext,
    pub frames: Vec<Frame>,
}

/// Parse a decrypted, header-validated payload into frames,
/// enforcing the packet-context rules from wire-format §57.
pub fn parse_payload(context: &PacketContext, payload: &[u8]) -> Result<ParsedPacket, PacketError> {
    if payload.len() > MAX_PACKET_SIZE {
        return Err(PacketError::TooLarge);
    }
    let frames = decode_frames(payload).map_err(PacketError::Frame)?;
    for f in &frames {
        check_context(context, f)?;
    }
    Ok(ParsedPacket { context: context.clone(), frames })
}

pub fn context_allows(context: &PacketContext, ty: umc_types::frame::FrameType) -> bool {
    use umc_types::frame::FrameType as T;
    use ShortPacketSpace::*;
    match (context, ty) {
        (_, T::PADDING) | (_, T::PING) | (_, T::ACK) | (_, T::CAPABILITIES) => true,
        (PacketContext::Initial | PacketContext::Handshake, T::AUTH | T::HANDSHAKE_DATA) => true,
        (PacketContext::Protected(_), T::STREAM | T::DATAGRAM) => true,
        (PacketContext::Protected(_), T::ROUTE_REQUEST | T::ROUTE_RESPONSE | T::ROUTE_ERROR) => true,
        (PacketContext::Protected(_), T::RELAY_OPEN | T::RELAY_STATUS | T::RELAY_DATA | T::RELAY_CLOSE) => true,
        (PacketContext::Protected(_), T::BUNDLE | T::BUNDLE_ACK) => true,
        (PacketContext::Protected(_), T::PATH_CHALLENGE | T::PATH_RESPONSE | T::PATH_STATUS | T::MIGRATE) => true,
        (PacketContext::Protected(_), T::KEY_UPDATE) => true,
        (PacketContext::Protected(_), T::NEW_CONNECTION_ID | T::RETIRE_CONNECTION_ID) => true,
        (PacketContext::Protected(_), T::PEER_HINT | T::SERVICE_HINT) => true,
        (PacketContext::Protected(_), T::MAX_DATA | T::MAX_STREAM_DATA | T::MAX_STREAMS) => true,
        (PacketContext::Protected(_), T::RESET_STREAM | T::STOP_SENDING) => true,
        (PacketContext::Protected(_), T::CONNECTION_CLOSE) => true,
        (PacketContext::Protected(SessionData | PathControl | RelayData), T::SESSION_TICKET) => true,
        _ => false,
    }
}

fn check_context(context: &PacketContext, frame: &Frame) -> Result<(), PacketError> {
    let ty = frame_type_of(frame);
    if context_allows(context, ty) {
        Ok(())
    } else {
        Err(PacketError::ContextViolation(ty))
    }
}

pub fn frame_type_of(frame: &Frame) -> umc_types::frame::FrameType {
    use umc_types::frame::FrameType as T;
    match frame {
        Frame::Padding => T::PADDING,
        Frame::Ping => T::PING,
        Frame::Ack(_) => T::ACK,
        Frame::ConnectionClose(_) => T::CONNECTION_CLOSE,
        Frame::Stream(_) => T::STREAM,
        Frame::ResetStream(_) => T::RESET_STREAM,
        Frame::StopSending(_) => T::STOP_SENDING,
        Frame::MaxData(_) => T::MAX_DATA,
        Frame::MaxStreamData(_) => T::MAX_STREAM_DATA,
        Frame::MaxStreams(_) => T::MAX_STREAMS,
        Frame::Datagram(_) => T::DATAGRAM,
        Frame::NewConnectionId(_) => T::NEW_CONNECTION_ID,
        Frame::RetireConnectionId(_) => T::RETIRE_CONNECTION_ID,
        Frame::PathChallenge(_) => T::PATH_CHALLENGE,
        Frame::PathResponse(_) => T::PATH_RESPONSE,
        Frame::PathStatus(_) => T::PATH_STATUS,
        Frame::Migrate(_) => T::MIGRATE,
        Frame::KeyUpdate(_) => T::KEY_UPDATE,
        Frame::RouteRequest(_) => T::ROUTE_REQUEST,
        Frame::RouteResponse(_) => T::ROUTE_RESPONSE,
        Frame::RouteError(_) => T::ROUTE_ERROR,
        Frame::RelayOpen(_) => T::RELAY_OPEN,
        Frame::RelayStatus(_) => T::RELAY_STATUS,
        Frame::RelayData(_) => T::RELAY_DATA,
        Frame::RelayClose(_) => T::RELAY_CLOSE,
        Frame::Bundle(_) => T::BUNDLE,
        Frame::BundleAck(_) => T::BUNDLE_ACK,
        Frame::PeerHint(_) => T::PEER_HINT,
        Frame::Capabilities(_) => T::CAPABILITIES,
        Frame::Auth(_) => T::AUTH,
        Frame::HandshakeData(_) => T::HANDSHAKE_DATA,
        Frame::SessionTicket(_) => T::SESSION_TICKET,
        Frame::ServiceHint(_) => T::SERVICE_HINT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameType as T;

    #[test]
    fn stream_allowed_in_protected_not_initial() {
        let payload = [0x10, 0x00, 0x00, 0x61];
        assert!(parse_payload(&PacketContext::Protected(ShortPacketSpace::SessionData), &payload).is_ok());
        assert_eq!(
            parse_payload(&PacketContext::Initial, &payload).unwrap_err(),
            PacketError::ContextViolation(T::STREAM)
        );
    }

    #[test]
    fn handshake_data_allowed_only_in_handshake_contexts() {
        let payload = [0x74, 0x00, 0x00];
        assert!(parse_payload(&PacketContext::Initial, &payload).is_ok());
        assert_eq!(
            parse_payload(&PacketContext::Protected(ShortPacketSpace::SessionData), &payload).unwrap_err(),
            PacketError::ContextViolation(T::HANDSHAKE_DATA)
        );
    }

    #[test]
    fn route_request_only_in_protected() {
        // Encode: type 0x48 (len-delimited), len 6, body.
        let payload = [0x48, 0x06, 0x63, 0x00, 0x08, 0x30, 0x00, 0x00];
        assert!(parse_payload(&PacketContext::Protected(ShortPacketSpace::SessionData), &payload).is_ok());
        assert_eq!(
            parse_payload(&PacketContext::Handshake, &payload).unwrap_err(),
            PacketError::ContextViolation(T::ROUTE_REQUEST)
        );
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p umc-wire packet`
Expected: FAIL — `packet` module missing from lib.rs.

- [ ] **Step 3: Add module and complete the `Frame` enum**

Add `pub mod packet;` to lib.rs. The `frame_type_of` match requires every `Frame` variant to exist; complete the `Frame` enum in `frame.rs` with the variants referenced across Tasks 9-14 (`NewConnectionId`, `RetireConnectionId`, `PathChallenge`, `PathResponse`, `PathStatus`, `Migrate`, `KeyUpdate`, `RouteRequest`, `RouteResponse`, `RouteError`, `RelayOpen`, `RelayStatus`, `RelayData`, `RelayClose`, `Bundle`, `BundleAck`, `PeerHint`, `Capabilities`, `Auth`, `HandshakeData`, `SessionTicket`, `ServiceHint`) plus their dispatch arms if not already added.

Run: `cargo test -p umc-wire`
Expected: PASS (39 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/src/packet.rs crates/umc-wire/src/frame.rs crates/umc-wire/src/lib.rs
git commit -m "feat(wire): packet parser with frame-context validation"
```

---

### Task 16: Official test vectors

**Files:**
- Create: `crates/umc-wire/tests/vectors.rs`

- [ ] **Step 1: Write the failing vectors test**

`crates/umc-wire/tests/vectors.rs`:

```rust
//! Official interop vectors (wire-format.md §78).
use umc_wire::header::{HeaderByte, LongHeader, LongPacketType, ShortHeader, ShortPacketSpace};
use umc_wire::pn::reconstruct;
use umc_wire::varint::{decode, encode};

#[test]
fn varint_vectors() {
    let cases: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (63, &[0x3F]),
        (64, &[0x40, 0x40]),
        (16_383, &[0x7F, 0xFF]),
        (16_384, &[0x80, 0x40, 0x00, 0x00]),
        (1_073_741_823, &[0xBF, 0xFF, 0xFF, 0xFF]),
        (1_073_741_824, &[0xC0, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (4_611_686_018_427_387_903, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
    ];
    for (v, expected) in cases {
        assert_eq!(&encode(*v).unwrap(), expected, "encode {v}");
        assert_eq!(decode(expected).unwrap().0, *v, "decode {v}");
    }
}

#[test]
fn packet_number_vectors() {
    // (truncated, bits, expected_largest_plus_one, result)
    assert_eq!(reconstruct(100, 8, 101).unwrap(), 100);
    assert_eq!(reconstruct(1, 8, 255).unwrap(), 257);
    assert_eq!(reconstruct(200, 8, 400).unwrap(), 456);
}

#[test]
fn header_byte_vectors() {
    assert_eq!(HeaderByte::LONG_INITIAL.encode(), 0b1000_0000);
    assert_eq!(HeaderByte::SHORT_SESSION.encode(), 0b0000_0000);
    assert_eq!(HeaderByte::decode(0b1000_0100).unwrap().pn_bits, 16);
}

#[test]
fn long_header_vector() {
    // Conceptual example from wire-format.md §80, serialized deterministically.
    let h = LongHeader {
        ptype: LongPacketType::Initial,
        version: 1,
        dcid: vec![0x11; 8],
        scid: vec![0x22; 8],
        token: vec![],
        payload_len: 64,
        packet_number: 4021,
        pn_bits: 16,
    };
    let enc = h.encode().unwrap();
    assert_eq!(enc[0], 0b1000_0000);
    assert_eq!(&enc[1..5], &[0, 0, 0, 1]);
    assert_eq!(enc[5], 8);
    assert_eq!(&enc[6..14], &[0x11; 8]);
    assert_eq!(enc[14], 8);
    assert_eq!(&enc[15..23], &[0x22; 8]);
    assert_eq!(enc[23], 0x00, "token length 0");
    assert_eq!(enc[24], 0x40, "payload length 64");
    assert_eq!(&enc[25..], &[0x0F, 0xB5], "pn 4021 as 2 bytes");
}

#[test]
fn short_header_vector() {
    let h = ShortHeader {
        space: ShortPacketSpace::SessionData,
        dcid: vec![0x33; 8],
        path_id: 1,
        packet_number: 4021,
        pn_bits: 16,
        key_phase: false,
    };
    let enc = h.encode().unwrap();
    assert_eq!(enc[0], 0b0000_0000);
    assert_eq!(&enc[1..9], &[0x33; 8]);
    assert_eq!(&enc[9..], &[0x01, 0x0F, 0xB5]);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p umc-wire --test vectors`
Expected: FAIL — test file exists, module not implemented (varint/header/pn modules missing).

- [ ] **Step 3: Run after all modules exist**

Run: `cargo test -p umc-wire --test vectors`
Expected: PASS (6 vector tests) — this is the first time the whole wire crate is locked by official vectors.

- [ ] **Step 4: Commit**

```bash
git add crates/umc-wire/tests/vectors.rs
git commit -m "test(wire): official interop vectors"
```

---

### Task 17: Fuzz smoke tests and proptest corpus

**Files:**
- Create: `crates/umc-wire/tests/fuzz_smoke.rs`
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/wire_parser.rs`

- [ ] **Step 1: Write the deterministic fuzz smoke test**

`crates/umc-wire/tests/fuzz_smoke.rs`:

```rust
//! Deterministic pseudo-fuzzing: feed seeded random buffers through the parser.
//! Runs on stable; never panics on malformed input.
use umc_wire::packet::{parse_payload, PacketContext};
use umc_wire::varint::decode as decode_varint;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_be_bytes();
            for (dst, src) in chunk.iter_mut().zip(v.iter()) {
                *dst = *src;
            }
        }
    }
}

const SEEDS: [u64; 4] = [0xDEAD_BEEF, 0xCAFE_F00D, 42, u64::MAX];

#[test]
fn parser_never_panics_on_random_buffers() {
    for seed in SEEDS {
        let mut rng = XorShift(seed);
        for _ in 0..25_000 {
            let len = (rng.next() % 300) as usize;
            let mut buf = vec![0u8; len];
            rng.fill(&mut buf);
            let _ = decode_varint(&buf);
            let _ = parse_payload(&PacketContext::Protected(umc_wire::header::ShortPacketSpace::SessionData), &buf);
            let _ = parse_payload(&PacketContext::Initial, &buf);
        }
    }
}

#[test]
fn parser_never_panics_on_corpus_edges() {
    // From wire-format.md §79.
    let corpus: &[&[u8]] = &[
        &[], &[0x00], &[0x08], &[0x48], &[0x48, 0x01], &[0x48, 0x06],
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        &[0x10, 0x00, 0xFF], &[0x60, 0x01, 0x00], &[0x00; 65_536],
    ];
    for buf in corpus {
        let _ = parse_payload(&PacketContext::Protected(umc_wire::header::ShortPacketSpace::SessionData), buf);
        let _ = parse_payload(&PacketContext::Initial, buf);
    }
}
```

- [ ] **Step 2: Run the smoke tests**

Run: `cargo test -p umc-wire --test fuzz_smoke`
Expected: PASS (2 tests, 100k random buffers). If any panic occurs, fix the parser before proceeding — the whole point of this task.

- [ ] **Step 3: Add the cargo-fuzz skeleton (nightly, optional)**

`fuzz/Cargo.toml`:

```toml
[package]
name = "umc-wire-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
umc-wire = { path = "../crates/umc-wire" }

[[bin]]
name = "wire_parser"
path = "fuzz_targets/wire_parser.rs"
test = false
doc = false
bench = false
```

`fuzz/fuzz_targets/wire_parser.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use umc_wire::packet::{parse_payload, PacketContext};

fuzz_target!(|data: &[u8]| {
    let _ = parse_payload(&PacketContext::Protected(umc_wire::header::ShortPacketSpace::SessionData), data);
    let _ = parse_payload(&PacketContext::Initial, data);
});
```

- [ ] **Step 4: Add fuzz targets to the workspace members list (commented as optional)**

Append to root `Cargo.toml`:

```toml
# Optional nightly fuzzing workspace (requires cargo-fuzz); uncomment when needed:
# members = [..., "fuzz"]
```

- [ ] **Step 5: Run full crate checks and commit**

Run: `cargo fmt --all --check && cargo clippy -p umc-types -p umc-wire -- -D warnings && cargo test -p umc-types -p umc-wire`
Expected: PASS — fmt clean, clippy clean, all tests green.

```bash
git add crates/umc-wire/tests/fuzz_smoke.rs fuzz/
git commit -m "test(wire): fuzz smoke tests and cargo-fuzz skeleton"
```

---

### Task 18: CI and coding standards enforcement

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `LICENSE-MIT`
- Create: `LICENSE-APACHE`
- Create: `CONTRIBUTING.md` (short pointer)

- [ ] **Step 1: Write the Tier-1 CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always

jobs:
  check:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-14, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - name: Format
        run: cargo fmt --all --check
      - name: Clippy
        run: cargo clippy --workspace --all-targets -- -D warnings
      - name: Test
        run: cargo test --workspace
```

- [ ] **Step 2: License files**

Copy the standard MIT and Apache-2.0 license texts into `LICENSE-MIT` and `LICENSE-APACHE` respectively (full canonical texts, e.g. from https://spdx.org/licenses/). Add to `README.md`:

```markdown
## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
```

- [ ] **Step 3: Contribution pointer**

`CONTRIBUTING.md`:

```markdown
# Contributing

See `spec/decisions.md` for the accepted architecture, `umeps/0001-process.md`
for the proposal process, and `GOVERNANCE.md` for roles and decisions.

Every change must pass `cargo fmt --check`, `cargo clippy -- -D warnings`,
and `cargo test --workspace`. Network-facing parsers require fuzz coverage.
```

- [ ] **Step 4: Run the checks locally**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: PASS on all three.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml LICENSE-MIT LICENSE-APACHE CONTRIBUTING.md README.md
git commit -m "ci: Tier-1 matrix, lint gates, license files"
```

---

### Task 19: Relocate the Go prototype

**Files:**
- Move: `core/**` → `prototype/go/**`
- Modify: `.gitignore`

- [ ] **Step 1: Move the prototype**

Run: `mkdir -p prototype && git mv core prototype/go`

- [ ] **Step 2: Add a prototype readme**

Create `prototype/go/README.md`:

```markdown
# Go Prototype (archived)

Pre-decision exploration of the UMP concepts in Go.

The accepted implementation is the Rust workspace described in
`spec/decisions.md` §4. This code is retained for reference only:
it is NOT maintained, does NOT implement the current specifications,
and MUST NOT be used as a compatibility reference.
```

- [ ] **Step 3: Update .gitignore if needed**

Run: `git status` — confirm no untracked Go artifacts remain.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: archive Go prototype under prototype/go"
```

---

### Task 20: Phase 0 completion gate

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Verify the full gate**

Run: `cargo fmt --all --check`
Expected: clean.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

Run: `cargo test --workspace`
Expected: all green.

Run: `cargo test -p umc-wire --test fuzz_smoke`
Expected: PASS (no panics on 100k+ random buffers).

Run: `cargo test -p umc-wire --test vectors`
Expected: PASS (official vectors lock the wire format).

- [ ] **Step 2: Update README with phase status**

```markdown
# Universal Mesh Core (UMC)

Reference implementation of the Universal Mesh Protocol (UMP/1).
Specifications live in `spec/`.

## Status

- [x] Phase 0: foundations — workspace, wire parser, vectors, fuzzing, CI
- [ ] Phase 1: secure direct communication
- [ ] Phase 2: node runtime
- [ ] Phase 3: routing and relaying
- [ ] Phase 4: mobility
- [ ] Phase 5: local mesh
- [ ] Phase 6: store-and-forward
- [ ] Phase 7: adversarial resilience
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: phase 0 complete"
```

- [ ] **Step 4: Confirm Phase 0 success criteria from `core.md` §64**

Checklist:

- [ ] Repository with build system (workspace, fmt, clippy)
- [ ] Coding standards enforced in CI (deny unsafe, -D warnings)
- [ ] CI runs on every change on Tier-1 platforms
- [ ] Wire parser: varints, byte strings, headers, packet numbers, all frames
- [ ] Official test vectors passing
- [ ] Fuzz smoke tests passing
- [ ] Threat model and security policy documents in place (already in `spec/`)
- [ ] Go prototype archived

---

## Phase 0 self-review

**Spec coverage:** `wire-format.md` §5 (varints) → Task 3; §6 (byte strings) → Task 4; §10-17 (headers) → Tasks 6-7; §19 (packet numbers) → Task 5; §21-22 (frame encoding, extension rules) → Task 8; §23-56 (all frames) → Tasks 8-14; §57 (packet-context restrictions) → Task 15; §78 (test vectors) → Task 16; §79 (fuzz corpus) → Task 17; `core.md` §46-49 (repo, testing) → Tasks 1, 17-18; `decisions.md` §4 (workspace) → Task 1; `core.md` §64 Phase 0 → Task 20.

**Known deferred:** header *decoding* (only encoding + header-byte parsing is implemented; full packet-header decode arrives with crypto in Phase 1 when header protection exists), ACK delay exponent semantics (session layer, Phase 1), stateless reset and version-negotiation packet encoding (Phase 1 handshake).

