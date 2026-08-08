# Gap-Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the gaps found in the 2026-08-07 spec/plan audit: wire the runtime enforcement that exists as dead library code, add persistence, build the congestion-control subsystem, complete the handshake flow, and land the missing plan tasks (metrics, resumption, TLS carrier, bindings, testing gates, process fixes).

**Architecture:** Phases A–J are independently executable units, ordered by value/effort. Phases A–C have full code-level tasks; phases D–J give precise file/API/test specs to be expanded into per-phase plan documents at execution time (the established repo convention). Every phase ends with the workspace gate: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.

**Tech Stack:** Rust workspace (existing crates), rusqlite (bundled), tokio, prost, serde; no new heavy dependencies unless a task says so.

**Audit provenance:** gaps from the 2026-08-07 audit (congestion.md, testing.md, security-operations.md, sdk.md, resource-limits.md, discovery.md, core.md, session.md, handshake.md, storage.md, identity-trust.md, control-api.md, carriers/{registry,tls-stream}.md, decisions.md) plus plan-task gaps from phases 7, 10, 11, 12, 13, 14. The audit documents live in the conversation history; each task cites its source.

---

## Phase A: Runtime enforcement wiring (highest value — code exists, daemon never drives it)

**Source:** audit items A.1–A.15, B.16–B.23, session.md §20–31, resource-limits.md §20/§24, bundles.md §11.

### Task A1: ACK handling and RTT sampling in the session

**Files:**
- Modify: `crates/umc-session/src/session.rs` (on_inbound match, add on_peer_ack sampling)
- Test: `crates/umc-session/tests/session_pipe.rs` (append)

**Problem:** `Session::on_inbound` drops `Frame::Ack` in `_ => {}`, and the daemon never calls `on_peer_ack` — RTT is never sampled in the running system (audit A.3).

- [ ] **Step 1: Write the failing test**

```rust
// tests/phase13 style helper: build a session, record a sent packet,
// deliver a peer ACK, assert rtt() became initialized.
#[test]
fn ack_sampling_initializes_rtt() {
    // reuse the pipe-test setup (client+server sessions from run_xx_handshake)
    let (cs, ss) = /* driver handshake */;
    // ... build client session with TEST_CLOCK
    let pkt = client.build_outbound(&TEST_CLOCK, Instant(1_000_000), &ping_payload()).unwrap().unwrap();
    // deliver to server, server acks
    let ack_payload = server.on_inbound(Instant(1_000_000), &pkt).unwrap();
    // client receives the ack; sent_at was 1_000_000, now is 1_000_100
    let _ = client.on_inbound(Instant(1_000_100), &ack_packet_from(ack_payload));
    assert!(client.rtt().initialized);
    assert_eq!(client.rtt().latest_rtt, 100);
}
```

- [ ] **Step 2: Run to verify it fails** (RTT stays uninitialized)
- [ ] **Step 3: Implement**

In `Session::on_inbound`, replace `_ => {}` handling: on `Frame::Ack(ack)`, call a new `fn apply_peer_ack(&mut self, ack: &AckFrame, now: Instant)` that (a) builds the flat ranges vec `[(first_range, 0), (gap, len)...]` from the ACK frame fields, (b) calls `self.sent.apply_ack(largest, &flat)`, (c) for each acked sent packet computes `sample = now.duration_since(sent_at).as_millis().saturating_sub(ack_delay_ms)` and feeds `self.rtt.sample(sample)` (congestion.md §8), and (d) returns the list of acked packet numbers so the daemon can run loss detection.

Signature: `pub fn apply_peer_ack(&mut self, ack: &umc_wire::frames::simple::AckFrame, now: Instant) -> Result<Vec<u64>, SessionError>` — check the actual `AckFrame` field names in `crates/umc-wire/src/frames/simple.rs` (largest/ack_delay/range_count/first_range/gaps) and adapt.

- [ ] **Step 4: Run tests, fix, commit** `feat(session): ACK processing and RTT sampling`

### Task A2: Loss detection + PTO driven by the daemon

**Files:**
- Modify: `bins/umcd/src/session_task.rs` (process_inbound_packet)
- Modify: `crates/umc-session/src/loss.rs` (expose armed timer API)
- Test: `bins/umcd/src/session_task.rs` unit test

**Problem:** `detect_lost_packets` and `pto` are never invoked (audit A.4–A.5).

- [ ] **Step 1:** In `process_inbound_packet`, after `session.apply_peer_ack` (Task A1), call `detect_lost_packets(&mut session.sent_state..., ...)` — check what `AckSendState` access the session exposes (add `pub fn sent_state_mut(&mut self)` if needed) — with `largest_acked` from the ACK frame, and push lost PNs into a `pending_retransmit` queue.
- [ ] **Step 2:** Add `pub fn pto(&self, rtt: &RttEstimator) -> Duration` call site: the session task arms `tokio::time::sleep(pto)` when it has pending retransmits or unacked ack-eliciting packets; on expiry, push a PING (probe) into the outbound (PTO backoff: double each consecutive expiry, reset on any ACK — track in a `pto_count`).
- [ ] **Step 3:** Retransmission: for each lost PN in the queue, rebuild the packet's payload — the session currently keeps NO payload copy; add `payload: Vec<u8>` to `SentPacket` (populated by `build_outbound`), and a `retransmit(pn)` path that re-sends the stored payload under a fresh PN (session.md §14). `build_outbound` records `payload: payload.to_vec()`.
- [ ] **Step 4:** Tests: unit test that a lost packet's payload is re-sent after loss detection fires; the pipe test still passes.
- [ ] **Step 5:** Commit `feat(session): loss detection and PTO in the daemon loop`

### Task A3: Idle timeout and draining

**Files:**
- Modify: `crates/umc-session/src/session.rs` (idle deadline)
- Modify: `bins/umcd/src/session_task.rs` (timer)
- Test: `crates/umc-session/tests/session_pipe.rs`

**Source:** session.md §6.4, §22.

- [ ] **Step 1:** Test: a session with no traffic for > IDLE_TIMEOUT_MS (30 s constant in session.rs, `pub const IDLE_TIMEOUT_MS: u64 = 30_000`) reports `idle_expired(now) -> bool`; `touch(now)` resets.
- [ ] **Step 2:** `Session` gains `last_activity: Option<Instant>` touched in `on_inbound`/`build_outbound`; `pub fn idle_expired(&self, now: Instant) -> bool`.
- [ ] **Step 3:** The session task's select loop adds a `tokio::time::interval(1s)` arm: if `session.idle_expired(now)`, send a CONNECTION_CLOSE (idle) and exit the loop. State `Draining` with a 3×PTO (min 1 s) deadline before final close; the existing `SessionState::Draining` enum is used (session.md §6.4).
- [ ] **Step 4:** Commit `feat(session): idle timeout and draining`

### Task A4: Keepalive

**Files:**
- Modify: `bins/umcd/src/session_task.rs`
- Test: unit test

**Source:** session.md §23.

- [ ] **Step 1:** Test: session idle for > 15 s (0.5 × IDLE_TIMEOUT) and ack-eliciting traffic present → the task emits a PING frame in the outbound.
- [ ] **Step 2:** In the same 1 s interval arm: if `idle > IDLE_TIMEOUT_MS / 2`, build a PING payload (`varint::encode(FrameType::PING.0)`) and send it (keepalive suppresses the idle close — record `last_activity`).
- [ ] **Step 3:** Commit `feat(session): keepalive pings`

### Task A5: Bounded sent-packet metadata

**Files:**
- Modify: `crates/umc-session/src/ack.rs`
- Test: `crates/umc-session/tests/proptest_replay.rs`-style unit test

**Source:** congestion.md §22, resource-limits.md §24 (16,384 cap).

- [ ] **Step 1:** Test: record 16,385 sent packets → the oldest is declared lost (returned from `record_sent` as a lost PN) and removed; memory stays ≤ 16,384.
- [ ] **Step 2:** `AckSendState::record_sent` enforces `MAX_OUTSTANDING_PACKETS: usize = 16_384`: when at cap, pop the oldest ack-eliciting packet, mark it lost (return its PN), push the new one.
- [ ] **Step 3:** Commit `fix(session): bound outstanding sent-packet metadata`

### Task A6: Stream-count cap

**Files:**
- Modify: `crates/umc-session/src/session.rs`
- Test: unit test

**Source:** resource-limits.md §20 (1,024 hard cap).

- [ ] **Step 1:** Test: 1,025th stream (via `open_stream` and via inbound `apply_stream_frame` creating a new id) → `SessionError::StreamLimit`.
- [ ] **Step 2:** `pub const MAX_STREAMS_PER_SESSION: usize = 1_024;` — `open_stream` and the `entry().or_insert_with` path both check `self.streams.len()` first.
- [ ] **Step 3:** Commit `fix(session): hard stream-count cap`

### Task A7: Anti-amplification enforcement

**Files:**
- Modify: `crates/umc-session/src/session.rs` (build_outbound)
- Modify: `crates/umc-session/src/path.rs` (call sites)
- Test: `crates/umc-session/tests/session_pipe.rs`

**Source:** session.md §26, congestion.md §18, resource-limits.md §18 (3× rule).

- [ ] **Step 1:** Test: on an unvalidated path, after receiving 100 bytes, sending > 300 bytes total is refused (`SessionError::AmplificationLimit`); after `confirm`, the budget is unlimited.
- [ ] **Step 2:** `Path::record_received(bytes, now)` and `record_sent(bytes)` already exist — wire them: `on_inbound` → `record_received`; `build_outbound` → check `send_allowance()` (3 × received − sent) on paths that are not yet validated, else `Err(SessionError::AmplificationLimit)`, then `record_sent`.
- [ ] **Step 3:** Commit `feat(session): anti-amplification budget`

### Task A8: Flow-control credit emission and reset handling

**Files:**
- Modify: `crates/umc-session/src/session.rs`
- Test: unit test + pipe test

**Source:** session.md §20, audit B.19 (MAX_* never emitted; RESET_STREAM/STOP_SENDING never handled).

- [ ] **Step 1:** Tests: (a) after `consume` crosses 50% of `max_data_local`, the session returns a MAX_DATA frame payload from a new `flow_control_frames(now) -> Vec<Vec<u8>>` accessor; (b) `Frame::ResetStream` → stream `recv_state` → `ResetRecvd`, `read_stream` returns `Reset`-shaped error; `Frame::StopSending` → the matching stream's send side is stopped.
- [ ] **Step 2:** `flow_control_frames`: when `consumed > max_data_local / 2`, emit MAX_DATA with `2 × max_data_local`; per-stream: emit MAX_STREAM_DATA when the stream's buffered consumption crosses half; emit MAX_STREAMS when `streams.len()` crosses 50% of the limit. The session task appends these to the outbound when non-empty.
- [ ] **Step 3:** `on_inbound` match gains `Frame::ResetStream(f)` and `Frame::StopSending(f)` arms (session.md §18.5) — check the wire frame field names in `crates/umc-wire/src/frames/stream.rs`.
- [ ] **Step 4:** Commit `feat(session): flow-control credit updates and reset handling`

### Task A9: Bundle expiry eviction in the daemon

**Files:**
- Modify: `bins/umcd/src/bundle_service.rs` (call `expire_old`)
- Modify: `bins/umcd/src/session_task.rs` (sweep arm)
- Test: umcd unit test

**Source:** bundles.md §11 (eviction never runs; expired bundles accumulate).

- [ ] **Step 1:** Test: admit a bundle with lifetime 1 ms, advance the clock past expiry, run the sweep → `list()` is empty and `count()` is 0; storage freed.
- [ ] **Step 2:** The existing 30 s bundle sweep (in `process_inbound_packet`'s `flush_pending_bundles`) also calls `bundle_service.expire_old(now)` first.
- [ ] **Step 3:** Commit `fix(umcd): bundle expiry eviction in the daemon loop`

### Task A10: Key-discard schedule

**Files:**
- Modify: `crates/umc-crypto/src/keys.rs` (replace the 2-line stub)
- Test: `crates/umc-crypto/src/keys.rs` tests

**Source:** plan phase 1 T14 (key-discard never populated), handshake.md §40.

- [ ] **Step 1:** Tests: initial keys discarded once a Handshake-space packet is successfully processed; handshake keys discarded once the session is confirmed (client/server finished validated); session keys retained until key update; `KeyDiscardSchedule::on_packet(space, confirmed)` drives it.
- [ ] **Step 2:** `pub struct KeyDiscardSchedule { initial_discarded: bool, handshake_discarded: bool }` with `should_discard_initial()`, `should_discard_handshake()`, `mark_initial_discarded()`, `mark_handshake_discarded()`; unit tests for the orderings (initial discarded before handshake keys exist; handshake only after confirmation).
- [ ] **Step 3:** Commit `feat(crypto): key-discard schedule`

### Task A11: Phase A gate

- [ ] Full workspace gate (fmt, clippy, test).
- [ ] Update `README.md` status? (No — phase statuses change only at plan completion; skip.)
- [ ] Commit nothing extra (A1–A10 commits stand).

---

## Phase B: Persistence (identity survives restart)

**Source:** audit B.5, core.md §19/§63, storage.md §20–21, plan phase 13 T1–T2.

### Task B1: Keystore hardening and wiring

**Files:**
- Modify: `crates/umc-storage/src/keystore.rs`
- Modify: `bins/umcd/src/state.rs`
- Modify: `bins/umcd/src/main.rs` (init + startup)
- Test: keystore tests + umcd test

**Problems:** daemon regenerates identity every boot (audit B.5); keystore file is 0644, salt from `DefaultHasher`, no integrity check at open (audit B.45).

- [ ] **Step 1:** Keystore fixes: (a) write the keystore file with mode 0600 (`std::fs::OpenOptions` + `set_permissions`); (b) replace the `DefaultHasher` salt with `blake2s("UMP-KEYSTORE-SALT-v1" || password)` (verify the current salt derivation and replace); (c) `open` verifies the check blob before returning (integrity check at open, not lazily).
- [ ] **Step 2:** Tests for (a)–(c): file mode is 0600; two opens with the same password produce identical seal/open results; opening with a wrong password fails at `open`.
- [ ] **Step 3:** `umcd --init` creates the keystore (existing behavior) AND seeds it: generate `NodeIdentity`, `store(Identity, b"node-identity", bytes)` — serialize the identity keypairs (IdentityKeyPair/StaticHandshakeKeyPair: store the 32-byte seeds; add `to_seed()`/`from_seed()` to `umc_crypto::signatures` if missing — SANCTIONED addition).
- [ ] **Step 4:** `RuntimeState::new` loads the identity from the keystore when present (unlock prompt is NOT viable in a daemon — use an `UMC_KEYSTORE_PASSWORD` env var or an empty-password dev default documented in config; choose env var, document); falls back to generate + persist when absent.
- [ ] **Step 5:** Tests: umcd test that two consecutive `RuntimeState::new` on the same data dir produce the SAME endpoint id; restart persistence end-to-end (spawn, record endpoint id, kill, respawn, same id).
- [ ] **Step 6:** Commit `feat(umcd): persistent node identity via keystore`

### Task B2: Peer/route record persistence

**Files:**
- Modify: `crates/umc-storage/src/records.rs` (replace 2-line placeholder)
- Modify: `bins/umcd/src/routing_service.rs` (load/save)
- Modify: `bins/umcd/src/discovery_service.rs` (load/save candidates)
- Test: storage unit tests + umcd restart test

**Source:** plan phase 13 T1, routing.md §24–25 (revalidation-as-candidate after restart).

- [ ] **Step 1:** `records.rs`: `PeerRecord { endpoint_id, first_seen, last_seen, trust_level, metadata }` and `RouteRecord` persisted as JSON rows in the `peer`/`route` namespaces (Store trait): `save_peer`, `list_peers`, `save_route`, `list_routes`, `clear_routes` (routes are revalidated, not trusted, after restart — mark stored routes `source=persisted` and let the cache treat them as candidates only).
- [ ] **Step 2:** `routing_service` loads routes at construction (marked stale/candidate) and saves on `record_route_response`; `discovery_service` saves candidates on upsert and loads at construction.
- [ ] **Step 3:** Tests: storage round trips; umcd restart test — a learned route survives restart as a candidate; a discovered candidate survives.
- [ ] **Step 4:** Commit `feat(storage,umcd): peer and route persistence`

### Task B3: Bundle metadata persistence

**Files:**
- Create: `crates/umc-bundle/src/persist.rs`
- Modify: `crates/umc-bundle/src/lib.rs` (module)
- Modify: `crates/umc-bundle/src/manager.rs` (load/save)
- Test: bundle tests + umcd restart test

**Source:** plan phase 13 T2, storage.md §6.3.

- [ ] **Step 1:** `persist.rs`: `BundleMeta { id, size, status, lifetime_ms, expires_at_ms, sender, replication_limit, created_at_ms }`; `save_meta(&dyn Store, meta)`, `load_all_metas(&dyn Store) -> Vec<BundleMeta>`; JSON in the `bundle` namespace keyed by the 32-byte id hex.
- [ ] **Step 2:** `BundleManager` gains `persist: bool` (or takes the store) — on admit: save meta; on evict/expire: delete meta; `BundleManager::restore(&dyn Store, ...)` reconstructs records for non-expired bundles (object store already holds the ciphertext — verify the object-store key convention matches the id).
- [ ] **Step 3:** `umcd` calls `restore` at startup; restart test: admit, respawn, `list()` shows the bundle.
- [ ] **Step 4:** Commit `feat(bundle): metadata persistence`

### Task B4: Event-log (audit) persistence

**Files:**
- Modify: `bins/umcd/src/event_log.rs`
- Test: umcd unit test

**Source:** core.md §15 audit logging, audit B.14.

- [ ] **Step 1:** `DaemonEvents` gains an optional `Store` handle: `push` also appends `{kind, at_ms, detail}` to the `api` namespace (bounded: cap the persisted ring at 10,000 entries with FIFO trim); `recent` reads the in-memory ring (unchanged fast path).
- [ ] **Step 2:** umcd wires the store; test: push → reopen → `recent` still shows the entry.
- [ ] **Step 3:** Commit `feat(umcd): audit event persistence`

### Task B5: Backup and restore

**Files:**
- Modify: `bins/umcd/src/main.rs` (CLI flags `--backup <path>` / `--restore <path>`)
- Create: `bins/umcd/src/backup.rs`
- Test: umcd integration-style unit test

**Source:** storage.md §20–21.

- [ ] **Step 1:** `backup.rs`: `export(store_path, out_path)` — copy the SQLite file with WAL checkpoint, plus keystore file; `import(store_path, in_path)` — validate the SQLite file (open + schema_version) before replacing; refuse import when the target has newer schema version (storage.md §21.4).
- [ ] **Step 2:** CLI: `umcd --backup out.tar` (tar not needed — plain directory copy or a single JSON+bytes container; choose a `.zip`-free simple format: a directory `backup/` with `node.db`, `keystore.bin`, `manifest.json`); `umcd --restore dir`.
- [ ] **Step 3:** Test: init → backup → wipe → restore → identity and routes survive (compare endpoint id).
- [ ] **Step 4:** Commit `feat(umcd): backup and restore`

### Task B6: Phase B gate

- [ ] Workspace gate (fmt/clippy/test). No extra commits.

---

## Phase C: Congestion control subsystem

**Source:** congestion.md (whole spec), core.md §33, decisions.md #20 ("internal mandatory subsystem").

### Task C1: CongestionController trait and Reno window

**Files:**
- Create: `crates/umc-session/src/congestion.rs`
- Modify: `crates/umc-session/src/lib.rs`
- Modify: `crates/umc-session/src/session.rs` (send gate)
- Test: `crates/umc-session/tests/congestion.rs`

- [ ] **Step 1:** Tests (congestion.md §24.1): slow start doubles cwnd per ACKed packet up to ssthresh; congestion avoidance adds 1/cwnd per ACKed packet above ssthresh; loss (3 duplicate/lost) → ssthresh = cwnd/2, cwnd = ssthresh (Reno); cwnd floor 2 × SMSS; `send_allowance(now) -> usize` respects `cwnd − in_flight`.
- [ ] **Step 2:** `pub trait CongestionController: Send { fn on_ack(&mut self, newly_acked: usize, now: Instant); fn on_loss(&mut self, pn: u64, now: Instant); fn on_pto(&mut self, now: Instant); fn send_allowance(&self) -> usize; fn cwnd(&self) -> usize; fn in_flight(&self) -> usize; fn on_packet_sent(&mut self, bytes: usize); fn on_packet_acknowledged(&mut self, bytes: usize); fn on_packet_lost(&mut self, bytes: usize); }` with `RenoCongestionController { cwnd, ssthresh, in_flight, smss }` (SMSS = 1,200, initial cwnd = 10 × SMSS, ssthresh = u64::MAX).
- [ ] **Step 3:** `Session` gains `congestion: Box<dyn CongestionController>` (default Reno): `build_outbound` consults `send_allowance()` (also `min` with flow-control credit and the A7 path budget); `apply_peer_ack` feeds `on_ack`/`on_packet_acknowledged`; `detect_lost_packets` results feed `on_loss`.
- [ ] **Step 4:** Commit `feat(session): Reno congestion controller`

### Task C2: Pacing

**Files:**
- Modify: `crates/umc-session/src/congestion.rs`
- Test: congestion tests

- [ ] **Step 1:** Tests (congestion.md §24.2): pacing rate = cwnd / smoothed RTT; burst cap = min(cwnd/2, 10 × SMSS); spaced sends respect the rate (a simulated clock advances and the controller releases tokens).
- [ ] **Step 2:** `PacingState { rate_bps, last_send, tokens }` inside the controller: `next_send_time(now) -> Option<Instant>`; the session task's send path awaits the pacing delay when set (the task already has the select loop — add a `tokio::time::sleep_until(next_send)` arm).
- [ ] **Step 3:** Commit `feat(session): pacing`

### Task C3: PTO backoff and probe packets

**Files:**
- Modify: `bins/umcd/src/session_task.rs`
- Modify: `crates/umc-session/src/loss.rs` (PtoState)
- Test: unit test

- [ ] **Step 1:** Test: consecutive PTO expiries double the timeout (1×, 2×, 4×, capped 60 s); any ACK resets the count; PTO expiry with no outstanding ack-eliciting sends a PING probe (congestion.md §10.3).
- [ ] **Step 2:** `PtoState { count, next_deadline }` in the daemon task; the existing A2 PTO arm now uses the doubling and resets on `apply_peer_ack`.
- [ ] **Step 3:** Commit `feat(session): PTO backoff`

### Task C4: Persistent congestion → path degradation

**Files:**
- Modify: `bins/umcd/src/session_task.rs`
- Modify: `crates/umc-session/src/path.rs` (wire `mark_degraded` callers)
- Test: unit test

- [ ] **Step 1:** Test: loss spans ≥ 3 PTOs (persistent_congestion true) → the path is marked degraded and the session emits a migration hint (PATH_STATUS or an event to the daemon → `session_closed`-style event `path_degraded`).
- [ ] **Step 2:** In the loss path: when the oldest and newest lost timestamps satisfy `persistent_congestion`, call `session.mark_path_degraded(path_id)` (new accessor) and push a daemon event.
- [ ] **Step 3:** Commit `feat(session): persistent-congestion path degradation`

### Task C5: Backpressure from carriers

**Files:**
- Modify: `bins/umcd/src/session_task.rs`
- Modify: `crates/umc-carrier/src/types.rs` (LinkProperties already has queue_bytes/capacity)
- Test: unit test

- [ ] **Step 1:** Test: when `LinkProperties::queue_bytes > 80%` of capacity, the session task pauses outbound sends (no new packets until below 50%).
- [ ] **Step 2:** The task's send path checks `link.properties()` before sending; a `backpressured` flag gates the send arms (congestion.md §16).
- [ ] **Step 3:** Commit `feat(session): carrier backpressure`

### Task C6: Congestion test suite + gate

- [ ] **Step 1:** Write the congestion.md §24 test matrix (21 tests: slow start, avoidance, loss halving, PTO doubling, pacing rate/burst, backpressure, forged-ACK rejection (ACK for unsent PN → `AckError::AcknowledgesUnsent` already exists — add a test asserting the controller does NOT react), in-flight bounds, control-traffic reserve (control packets bypass cwnd — `control: true` flag on the outbound path skips the allowance check)).
- [ ] **Step 2:** Commit `test(session): congestion conformance suite`
- [ ] **Step 3:** Phase C gate (fmt/clippy/test).

---

## Phase D: Handshake completion

**Source:** audit B.24–B.30, plan phase 12 T1–T2, phase 14 T1–T2/T4–T5. Expand into `2026-08-07-phaseD-handshake.md` when executing.

### Task D1: Initial/Hs packet protection (no plaintext handshake messages)
- Modify `umc-core/src/node.rs` (client) and `bins/umcd/src/main.rs` (server): CLIENT_HELLO/SERVER_HELLO travel inside Initial-protected packets (`derive_initial_keys` + `PacketKeys::seal`); client pads Initials to ≥ 1,200 B (wire-format §13); the raw plaintext fallback path is removed. The daemon's `initial.rs` already decrypts inbound Initials — outbound must encrypt.
- Tests: two-node live handshake still passes with protected messages; a plaintext hello is rejected.

### Task D2: CLIENT_AUTH over the wire (real client static key)
- `Node::connect` sends CLIENT_AUTH after SERVER_HELLO (client static + binding + signature encrypted with the client-auth key, per the T13 driver layout); the daemon's accept loop completes the two-step responder (`complete_handshake(auth_bytes)` exists in `handshake_responder.rs`) and verifies the static key — replacing the ephemeral-as-static provisional (main.rs:263 comment).
- Tests: the phase12 two-node flow with the REAL static key; a tampered CLIENT_AUTH is refused.

### Task D3: SERVER_FINISHED + CLIENT_FINISHED validation
- The responder emits SERVER_FINISHED (signature + finished MAC) after CLIENT_AUTH; the client validates it and sends CLIENT_FINISHED; session secrets are only used after confirmation. The driver code in `xx.rs` is the reference layout.
- Tests: finished-MAC mismatch fails the handshake.

### Task D4: Version negotiation
- Emit a Version-Negotiation packet when `supported_protocol_versions` excludes 1 (wire `LongPacketType::VersionNegotiation` exists); the client retries with a supported version; `respond_hello` inspects the offered versions instead of hardcoding (handshake_responder.rs:204).
- Tests: client offering only version 2 gets a VN packet and retries with 1.

### Task D5: Capability negotiation
- `ClientHello.capabilities_hash` computed from a canonical capability set; the server selects and binds it into the transcript (T13 driver layout); `CapabilitiesFrame` emission after handshake.
- Tests: mismatched capability hashes fail; selected capabilities appear in the session.

### Task D6: Stateless reset
- `crates/umc-session/src/reset.rs`: `accept_reset(token)` matching against the connection-id reset tokens (cid.rs has them); on match, emit a rate-limited stateless-reset packet (fixed pattern, session.md §31); the daemon maps it to a `session_closed` event.
- Tests: matching token resets; unknown token ignored; rate limit (1 per min per connection).

### Task D7: Session resumption (IK mode)
- `umc-handshake/src/ik.rs`: IK transcript mode (static-only DH), `build_resumption_hello(psk, ticket)`, `validate_resumption`; `NEW_SESSION_TICKET` emission by the daemon at session end; `SESSION_TICKET` handling in the session task; PSK from `umc_session::ticket::resumption_psk`; resumption ticket persistence via the B3 store.
- Tests: full resume round trip (ticket → resume → secrets match); stale/unknown ticket refused. Phase 12 T1–T2 are this task.

### Task D8: Short-header header protection
- `crates/umc-session/src/packet.rs` build/parse paths apply the header-protection mask (`umc_crypto::header_protection::protect/unprotect` with the session HP key — derive `hp_key` from the traffic secret via `expand_label(secret, "hp key", ...)`; check what the crypto crate exposes and add the label if missing, SANCTIONED) to the packet-number bytes and key-phase bit of short-header packets (wire-format §18). The daemon and test clients adopt it on both sides.
- Tests: a protected packet's PN bytes differ from plaintext; unprotect round-trips; the phase1/phase8 live flows still pass (both ends updated in lockstep).

### Task D9: Phase D gate
- Workspace gate; note explicitly: 0-RTT early data remains deferred (spec-permitted; `EARLY_DATA_REJECTED` const stays unused with a doc note).

---

## Phase E: Observability

**Source:** core.md §41–42/§61, control-api §42, audit B.1–B.4, plan phase 13 T3–T4.

### Task E1: Leveled logging (privacy-aware — privacy.md §37, §70)
- Add `log` + `env_logger` to umcd (RUST_LOG-driven); replace the `println!`/`eprintln!` debug lines in `session_task.rs`, `carriers.rs`, `main.rs` with `log::debug!/info!/warn!`; keep the `[session]` startup lines as `log::info!`.
- Safe logging defaults (privacy.md §37, P1): `info` and below MUST NOT contain endpoint ids, physical addresses, or full DCIDs — the session/peer prints use truncated suffixes (e.g. the last 4 bytes hex) at info, full values only at `debug`; a `log_redact` helper (SANCTIONED) centralizes the truncation; the default `RUST_LOG=info` shows no identity material.
- Tests: a unit test asserts the logger initializes and one line is emitted; a test asserts a session-active line at info contains NO full endpoint id (only the truncated suffix).

### Task E2: umc-metrics crate
- Create `crates/umc-metrics` (member): `Registry { counters: HashMap<&'static str, AtomicU64>, gauges: HashMap<&'static str, AtomicI64> }`, `incr(name, n)`, `set(name, v)`, `snapshot() -> Vec<(String, u64)>`; label support `name{label=val}` as part of the name string; cardinality cap (1,024 distinct names, drop beyond with a warning).
- Wire the daemon: counters for sessions (open/closed/active gauge), relay circuits, bundles admitted/expired, handshake successes/failures, control requests by service, packets sent/received, retransmissions, lost packets, path migrations. `GetMetricsSnapshot` + `GetSubsystemHealth` handlers (server.rs) return the snapshot.
- Tests: registry unit tests; server dispatch tests for the two new handlers.

### Task E3: Telemetry opt-in
- Config `telemetry_enabled: bool` (exists in the proto NodeConfig): when true, the daemon dumps the metrics snapshot to a JSONL file in the data dir every 60 s (`data_dir/telemetry.jsonl`); network telemetry export stays out of scope (documented).
- Test: config flag toggles the dump task.

### Task E4: CLI completion (phase 2 T13 gap)
- `bins/umc`: add `init`, `run`, `stop` (control-socket Shutdown), `identity create/inspect/rotate-handshake-key`, `doctor` with real output (invoke the daemon's Doctor over the control socket), `sessions list/close`, `routes list/invalidate`, `peers list` (from PeerService once F3 lands).
- Tests: CLI unit tests for arg parsing; smoke against a live daemon.

### Task E5: Phase E gate

---

## Phase F: Control API + SDK surface

**Source:** control-api.md §24–43, audit J.71–J.83, sdk.md (whole), plan phase 10 T4, phase 14 T13–T14.

### Task F1: Envelope-level protocol completion (error privacy — privacy.md §68)
- Error privacy (privacy.md §68): before authentication, `unknown service` / `private service` / `blocked requester` / `invalid credential` responses are indistinguishable (all return the same generic `Unauthenticated`/`NotFound` shape); the existing dev-token gate already returns `Unauthenticated` — extend so service-specific errors are only distinguishable AFTER successful hello auth.
- Tests: an unauthenticated request for a nonexistent service returns the SAME response as one for a real-but-private service.
- Sequence validation on the server path (use `umc_control::conn::SequenceTracker` — server.rs never imports it); `Cancel` and `GoAway` bodies handled (cancel maps to `RequestCancelled`; go-away drains then closes); idempotency (request-id cache, 10 min TTL, replay returns the stored response); pagination for list endpoints (`PageToken` from `pages.rs`); per-method capability authorization (the F2 grants table); OS peer-credential auth (SO_PEERCRED via `std::os::unix::net` when available, dev fallback).
- Tests: sequence violation rejected; idempotent replay; paginated list; cancel mid-flight.

### Task F2: IdentityService (9 RPCs) + CarrierService (10)
- Identity: ListIdentities (keystore-backed), GetIdentity, CreateIdentity, RotateHandshakeKey (re-sign the binding, sequence +1 — handshake.md §33), RotateIdentityKey, ExportPublicIdentity, ExportSecretIdentity (scoped, password-wrapped), ImportIdentity (validation), DeleteIdentity.
- Carrier: ListCarrierTypes (registry + registered), ListLinks (session links), GetLinkProperties, GetLinkStats, Dial, Listen, CloseLink (close the session/link).
- Tests: dispatch tests per method; rotate-handshake-key changes the binding and persists.

### Task F3: PeerService (10) + RouteService (4) + SessionService (4)
- Peer: ListPeers, GetPeer, AddPeerHint, RemovePeer, SetTrustState (wires trust.rs), BlockPeer/UnblockPeer (wires block.rs — this is security-operations §16.2), CreateInvitation/ImportInvitation/RevokeInvitation (wires invitation.rs — discovery.md §24.1).
- Route: ListRoutes, GetRoute, ProbeRoute (sends a route request), InvalidateRoute (cache removal + ROUTE_ERROR).
- Session: ListSessions, GetSession, CloseSession (idle-close the session task), ListStreams.
- Tests: dispatch tests; BlockPeer stops future sessions (accept loop checks blocklist).

### Task F4: ApplicationService (18) + bundle/relay remaining
- App: RegisterApplication, UnregisterApplication, ListApplications, GetApplication, PublishEndpointHint, Connect, Listen, AcceptSession, CloseSession (app-scoped), OpenStream, AcceptStream, SendStreamData, ReceiveStreamData, CloseStream, ResetStream, SendDatagram, ReceiveDatagram, GetDeliveryEvents — the ones with runtime backing (registry + app channels from phase 9; stream/datagram via the session bus) work; the rest return `Ok` with documented no-op or `Unimplemented` with a clear reason. Sanctioned: implement the runtime-backed set (registry/list/publish/hint/connect/listen) fully; stream/datagram delivery through the session bus.
- Bundle: GetBundle, DeleteBundle. Relay: GetRelayStatus, UpdateRelayPolicy, ListRelayCircuits, CloseRelayCircuit.
- Plugin (phase 14 T12): PluginService — ListPlugins, GetPluginStatus, EnablePlugin, DisablePlugin, ReloadPlugin — wired to `umc_plugin`'s registry (load manifests, mark enabled/disabled; dynamic loading stays out of scope per the plugin-security model).
- Tests: dispatch tests for every newly implemented method.

### Task F5: EventService Subscribe/Unsubscribe
- Subscription channels: `Subscribe { classes }` opens an mpsc event stream (per-connection task); `Unsubscribe` closes it; EventAck not required (at-most-once); backlog cap 1,024 events per subscriber (drop-oldest).
- Tests: subscribe receives events; unsubscribe stops delivery.

### Task F6: TokenService (4)
- ListGrants, CreateToken (wires auth.rs `create_token` with entropy), RevokeToken, InspectCurrentGrant (from the connection's hello auth).
- Tests: token lifecycle.

### Task F7: SDK application surface (sdk.md §8–32)
- `crates/umc-sdk`: `Endpoint` (create/load via identity import), `SessionHandle`, `StreamHandle`, `Datagram` API, `Listener`, `ServiceRegistry` (protocol ids), `DeliveryEvent` enum (ACKNOWLEDGED/LOST/RESET/CANCELLED), `Policy` (require_end_to_end_encryption, allow_relay, path_strategy), backpressure (bounded send returns WouldBlock), expanded `ClientError` (~19 categories + mapping table), opaque handles with generation checks.
- Where a feature needs daemon RPCs that exist, the SDK calls them; where the daemon lacks runtime backing, the SDK type exists with a documented `Unsupported` error (no silent no-ops).
- Tests: the sdk.md §32 set (24 tests) — the majority are request-shape/unit tests; live tests reuse the daemon harness.

### Task F8: Phase F gate

---

## Phase G: Trust, security, and process

**Source:** identity-trust.md §13–24, security-operations.md §11–21, threat-model.md §48–54, audit B.47–B.50, E.40, plan phase 14 T7/T9.

### Task G1: Trust states per spec
- `umc-core/src/trust.rs`: replace the 5 states with the spec's 7 (Unknown/Observed/Introduced/Trusted/Restricted/Blocked/Revoked); `effective_trust_level` maps defaults (Observed for authenticated-unknown); transition matrix + audit events; `SetTrustState` (F3) uses it.
- Tests: every transition validates; restricted peers get refused sessions with the right close reason.

### Task G2: Trust graph and introductions
- `umc-core/src/trust.rs` (or new `graph.rs`): introducer edges (`introduce(introducer, introduced, scope, expiry)`), transitive trust at depth ≤ 2 for Introduced, scope/expiry checks; persisted via the B2 records store.
- Tests: introduction grants Introduced trust; expired/out-of-scope introductions don't.

### Task G3: Revocation and TOFU
- `umc-core/src/revocation.rs` (or in trust): revocation records (endpoint id → revoked sequence/not_after, revoker id); the daemon's session establishment (responder `complete_handshake` + client side) checks the binding against the revocation store and the TOFU first-seen store before accepting (identity-trust.md §13, §16).
- Tests: revoked binding refused; first-seen mismatch (TOFU) refused with `IDENTITY_REVOKED`-style close.

### Task G4: Security-operations basics
- `SECURITY.md`: real contact (placeholder removal — ask the user for the address or mark `TBD-contact` explicitly), report policy, 90-day disclosure SLA.
- Emergency disablement: config keys `disabled_protocol_versions`, `disabled_crypto_profiles`, `disabled_carriers`, `disable_public_relay` honored at runtime (accept loop + handshake responder check them) (security-operations.md §15.2).
- Release manifest: `docs/RELEASE-MANIFEST.md` template + a `scripts/` signing stub (ed25519 sign of the manifest; verification tool) — signing KEY management documented, revocation of signing keys via the trust store.
- Tests: disabled carrier refuses dial/listen; disabled version returns VN/UNSUPPORTED; manifest sign/verify round trip.

### Task G5: Threat-model assessment output
- `docs/threat-model-assessment.md`: per-component threat→defense mapping (from spec/threat-model.md), residual-risk register with owner/status, unsafe-code inventory (`grep -rn "unsafe" crates/`), crypto review notes, adversarial-simulation status (links the J3 suite).
- No code — documentation task.

### Task G6: Phase G gate

---

## Phase H: Protocol completion (routing/relay/bundles/discovery)

**Source:** routing.md §13/§27/§16.6/§19, relay.md §11.5, bundles.md §7/§8.2/§12.2/§14, discovery.md §13/§15/§24, audit H.64–H.68, plan phase 14 T8/T10.

### Task H1: Multi-hop route-request forwarding
- `bins/umcd/src/session_task.rs`: on ROUTE_REQUEST with `hop_limit > 0` and no local match, forward to up to `DEFAULT_FANOUT` (3) other peers via their session bus outbound (decrement hop_limit, record the upstream in reverse state); respond to the requester per routing.md §13; `ROUTE_ERROR` frames handled with the code table (wire `frames/routing.rs` has RouteErrorFrame).
- Tests: 3-node A→B→C route discovery (phase12 harness, three daemons); TTL prevents loops.

### Task H2: Relay authorization validation
- `RELAY_OPEN.authorization` bytes validated in `session_task.rs` relay arm (relay.md §11.5): parse the authorization (carrier binding + ticket shape — define a minimal `RelayAuthorization { relay_endpoint_id, expiry_ms, nonce }` HMAC-BLAKE2s signed by the relay's identity key); admission refuses when invalid/expired.
- Tests: valid authorization accepted; forged/expired refused.

### Task H3: Bundle custody and large-bundle transfer
- Custody: on delivery, `CustodyAccepted` records the transfer (manager status), custody bundles are exempt from expiry eviction until the custody deadline (bundles.md §19.1); explicit release on delivery ack.
- Large transfer: bundles > MTU split into 256 KiB stream chunks (BUNDLE frame carries chunk index/end — check wire `BundleFrame` fields; if absent, add `chunk_index`/`chunk_final` fields SANCTIONED — wire-format change documented in decisions.md); reassembly on the receiver (bounded, 4 MiB).
- Duplicate cache: bounded (1,024) post-removal bundle-id cache with TTL (bundles.md §12.2).
- Tests: custody exemption, chunked transfer round trip, replayed bundle after eviction is rejected.

### Task H4: Envelope sealing on the sender
- `umc_bundle::envelope::seal_bundle` used by the bundle sender path (daemon `CreateBundle` handler): envelope with destination public key encryption (or the provisional shared-key scheme — use `dh_ss`-style derived key; document the scheme choice in decisions.md); the daemon stores the sealed envelope; receivers open with their identity.
- Tests: seal→open round trip with two identities.

### Task H5: PEER_HINT exchange and static peers
- Session task: on session establishment and every 30 s, build and send a PEER_HINT frame (discovery_service `build_hint`); inbound `Frame::PeerHint` → `apply_received_hints` (hints.rs — currently falls through `_ => {}`).
- `bins/umcd/src/static_peers.rs`: config `static_peers: [{endpoint_id, carrier, address}]` dialed at startup and on failure (bootstrap — discovery.md §15).
- Tests: hint exchange between two daemons populates candidate tables; a static peer is dialed at startup.

### Task H6: Invitation control surface + CLI
- Wires F3's invitation RPCs to `umc_discovery::invitation` (create/validate/revoke); CLI `umc invite create/import/revoke` and `umc peer add/remove/list`.
- Tests: invite round trip through the control API.

### Task H7: Phase H gate

---

## Phase I: Carriers + bindings + phase 7 leftovers

**Source:** carriers/tls-stream.md, carriers/registry.md, audit I.69–I.70, plan phase 7 T1/T3/T5, phase 10 T1–T4.

### Task I1: TLS-stream carrier
- Create `carriers/umc-carrier-tls` (rustls 0.23, tokio-rustls): profile `ump.tls-stream/1` per tls-stream.md — TLS 1.3, STREAM_FRAMED (reuse the tcp framing module — extract it into a shared `umc-carrier-common` or copy with attribution), channel exporter binding (`exporter` secret → instance data), error mapping, backpressure, MTU 65,535.
- Tests: 7 interop-style tests (handshake, exporter match, echo, oversize, close, TLS-failure mapping, backpressure) + a live echo over TLS in tests/phaseI.

### Task I2: Carrier registry mechanism
- `crates/umc-carrier/src/registry.rs`: a `CarrierRegistry` with allocation status (stable/experimental), the `ump.tls-stream/1` experimental entry; `register`/`status`/`list`; the daemon's carrier config validates against it (registry.md §2.1/§2.4).
- Tests: registry lifecycle; unknown carrier type rejected.

### Task I3: PSK-XX handshake mode
- `umc-handshake/src/psk.rs`: MODE_PSK_XX transcript (PSK mixed into extract before DH_ee), `PskConfig`; client/server helper functions mirroring the XX driver.
- Tests: both sides derive matching secrets; wrong PSK fails.

### Task I4: Sybil grouping
- `umc-routing/src/sybil.rs`: group requesters by (source prefix, capabilities hash); per-group request budget (routing.md/security: 10 requests/min per group); EnumerationGuard integration.
- Tests: a burst across 5 faked identities in one group is rate-limited as one.

### Task I5: Phase 10 bindings
- Python: `bindings/python/` — pure-stdlib framing client (4-byte BE length), `umc_pb2.py` generated from api/umc.proto (grpcio-tools OR hand-written minimal prost-equivalent for the messages the client uses — prefer grpcio-tools), `Client` with hello/request/status/config/events; `pytest` suite (framing, hello, request, error paths) against a live daemon.
- C ABI: `crates/umc-sdk-c` (cdylib): opaque handles (`umc_handle_t` with generation), versioned `umc_sdk_version()`, `umc_client_new/connect/request/close`, `umc_status`; `include/umc/umc.h`; a C smoke test compiled with `cc` in CI or a Rust test invoking the FFI.
- Tests: pytest for Python; the C smoke test; both against the phase12-style daemon harness.

### Task I6: Phase I gate

---

## Phase J: Testing gates + process closure

**Source:** testing.md (whole), threat-model.md §49, audit C.22–C.33, E.40, plan phase 13 T5, phase 14 T15–T16.

### Task J1: Fuzz targets to 11 + corpus + CI
- Add targets: `handshake_encoding.rs` (encoding.rs messages), `bundle_frame.rs` (bundle frames — phase 14 E11), `control_envelope.rs` (framing+envelope), `carrier_framing.rs` (the tcp length framing), `session_packet.rs` (protected packet parse+session), `identity_binding.rs` (binding decode+validate), `route_frames.rs`, `plugin_manifest.rs`, `db_recovery.rs` (SQLite reopen on corrupt bytes) — to reach testing.md §11.1's 11 targets.
- Corpus: seed `fuzz/corpus/` with the phase-0 vectors + edge corpus.
- CI: `.github/workflows/fuzz.yml` — nightly cargo-fuzz run (10 min per target) + the smoke corpus in the main CI.
- Tests: each target runs in the smoke harness (stable-friendly, like fuzz_smoke).

### Task J2: Deterministic simulator
- `tests/simulation/` crate: `SimClock` (advance(n)), `SimEntropy`, an in-memory `SimLink` pair (bounded queue, loss/duplicate/reorder injection, delay), and a two-node harness: run a full session with injected loss; assert recovery (retransmission, PTO) under deterministic schedules (testing.md §12).
- Tests: the phase12/phase14 flows rerun inside the simulator with loss injection.

### Task J3: Adversarial suite (threat-model §49, 22 scenarios)
- `tests/phaseJ/adversarial.rs`: the 22 scenarios as table-driven tests where possible — e.g., forged ACKs, replay of Initials, oversized headers, PN flood, handshake-request floods (tracker), amplification attempts (A7 budget), token brute force (rate-limited), malformed bindings, unknown-critical frames, fragmented frames, encrypted-garbage floods, connection-id exhaustion, stream-id reuse (exists), path-confusion (MIGRATE without validation), reset-token guessing, bundle replay (H3), relay auth forgery (H2), route-request loops (H1 TTL), control-API flooding (F1 rate limits), plugin manifest abuse, telemetry misuse.
- Each scenario: test + expected close/refusal behavior.

### Task J4: Benchmarks and soak
- `benches/` in umc-wire (varint, packet parse), umc-crypto (seal/open), umc-session (on_inbound); criterion dev-deps.
- Soak: `tests/soak/` — a 10-minute (CI-nightly, 60 s locally) two-node session with continuous streams/datagrams; assert no memory growth beyond a bound and no panics.

### Task J5: Coverage and CI gates
- Enable `cargo llvm-cov` (or `tarpaulin` fallback) in CI: gate on ≥ 70% line coverage for umc-wire/umc-crypto/umc-handshake/umc-session; report artifact.
- CI matrix gains linux-aarch64 (testing.md §17.1 Tier-1) via cross/self-hosted note (sanctioned: document as `matrix.note` if the runner is unavailable — do NOT add a broken job).

### Task J6: Process closure
- Update `spec/decisions.md`: record ALL implementation decisions (fixed-layout frame dispatch, provisional header protection, relay-status length-delimited resolution, TCP carrier bounded-reads design, plugin in-process capability model, envelope sealing scheme, TLS carrier experimental status, decisions #19/#20 status corrections, 0-RTT deferral, resumption timeline) — each as a dated entry with the resolved status. Also resolve the still-open decisions listed in the audit (B.51–B.55).
- `docs/COMPATIBILITY.md`: the release version matrix (compatibility.md §11.3), experimental feature marking (the TLS carrier), deferred capabilities (0-RTT, multi-hop relay, custody).
- SBOM: `cargo sbom` or a vendored `cargo metadata --format-version 1 > sbom.json` job in CI (security-operations.md §13.1).

### Task J7: Final gate + README status refresh
- Workspace gate.
- README: correct the phase 10–14 status lines (they currently overstate completion), add the gap-closure phases A–J with checkboxes.

---

## Self-Review Notes (writing-plans skill)

- **Spec coverage:** congestion.md → C1–C6; testing.md → J1–J5; security-operations → G4 + J6 (SBOM); sdk.md → F7; resource-limits → A5–A8 + F1 (rate limits) + G4; discovery.md → H5–H6; core.md → B1 (identity), E1–E4, C (congestion), G (policy via F-grants); session.md → A1–A8, D6; handshake.md → D1–D5, D7, A10; storage.md → B1–B5; identity-trust.md → G1–G3; control-api.md → F1–F6; carriers → I1–I2; decisions.md → J6; threat-model.md → G5 + J3.
- **Known non-goals (documented, not tasks):** 0-RTT early data, internet-scale discovery (DHT/HTTPS bootstrap), plugin process isolation (capability model is the boundary), multi-hop relay construction, relay multipath/store-forward mode, per-plugin resource budgets, telemetry network export, release signing keys provisioning.
- **Type/API consistency:** tasks reference existing names (AckFrame, build_outbound, apply_peer_ack, detect_lost_packets, force_validate, SessionError, DaemonEvents, CandidateTable) — verify against the code before writing each task's code; the dispatcher pattern is subagent-driven with corrections (established).
- **Plan-task coverage:** phase 7 T1/T3/T5 → I3/I4/I1; phase 10 → I5; phase 11 → documented deferral (capability model is the boundary); phase 12 T1/T2/T3 → D7/D6; phase 13 T1–T5 → B2/B3/E2/E3/J1; phase 14 T1–T14 → D4/D8/D2–D3/D5/D1/D9(no-op)/G1–G3/H1/H2/H5/F4(plugin)/F7.


---

## Phase K: Privacy (spec/privacy.md — P0–P3 ladder)

**Source:** spec/privacy.md §4-77. The conformance ladder is §76: P0 (Secure) is mostly met today; this phase delivers P1 fully and the P2/P3 mechanisms the architecture requires, keeping expensive anonymity opt-in (§70). Future work (§77) — anonymous credentials, PSI, PIR, mix modes — is explicitly out of scope and documented.

### Task K1: Privacy profiles and defaults
- `crates/umc-core/src/privacy.rs` (SANCTIONED new module): `#[derive(...)] pub enum PrivacyProfile { P0, P1, P2, P3 }` with `as_str()` ("p0".."p3"), `from_str`, `cumulative(profile) -> bool` (P2 implies P1+P0).
- `NodeConfig` gains `privacy_profile: String` (default "p0" — privacy-preserving defaults §70: secure by default, anonymity opt-in) and `privacy_policy_override: Option<String>` (local policy may RAISE the effective profile, never lower it — §43).
- The daemon exposes the effective profile via GetStatus (the NodeStatus proto may need a field — SANCTIONED proto addition `privacy_profile` string) and the config surface.
- Tests: parse/round trip; cumulative checks; override raises (p0 app + p1 policy → p1 effective); an override cannot lower.

### Task K2: Privacy negotiation (fail-closed)
- The capabilities negotiation from D5 carries privacy: extend `canonical_capabilities()` with a `privacy` entry whose value is the daemon's max supported profile (v1: "p1" — see K3); the CLIENT requests `minimum_privacy` — SANCTIONED: reuse the D5 padding-hash convention — the ClientHello's capabilities_hash already binds the client's set; add the requested minimum as a capabilities entry `privacy-min=p1` computed into the hash; the server verifies: if the requested minimum exceeds the daemon's supported profile → the handshake FAILS EXPLICITLY (an error close, never a silent downgrade — §42, §55).
- The session records `effective_privacy: PrivacyProfile` (from the negotiation); `Session::privacy_profile()` accessor.
- Tests: a client requesting p2 against a p1 daemon → handshake refused with the documented error; a p0 request against a p1 daemon → session at p1 (local policy raise); the negotiation is bound to the transcript (the hash is in the ClientHello — a tampered minimum fails the hash check).

### Task K3: P1 — identity-hiding handshake and ephemeral identifiers
- Audit the handshake for identity disclosure (privacy.md §6-7): the identity binding travels inside CLIENT_AUTH (encrypted under the provisional auth key — unauthenticated observers see ciphertext ✓); the SERVER_HELLO carries no identity ✓; the daemon's `[session] active with peer` line moves to the E1 redaction. Verify + document each disclosure point.
- Ephemeral identifiers (§7): per-session DCIDs exist; add periodic DCID rotation — the daemon's session task rotates the connection ID every 10 minutes via the existing cid.rs manager (issue/retire prior) and emits NEW_CONNECTION_ID (the wire frame exists); the peer adopts it.
- Bounded peer exchange (P1): the discovery service's PEER_HINT build is capped (already); ensure no full-table export — the ListCandidates control API caps at 100 (already).
- Tests: handshake trace contains no persistent identity in plaintext (assert the wire bytes of the CLIENT_HELLO/SERVER_HELLO carry no identity key material); DCID rotation round trips through a live session.

### Task K4: P1 — privacy-aware discovery
- Discovery (privacy.md §31-33): the candidate table upsert retains candidates only within their TTL (already); add: candidates with `LocalUseOnly`/`DoNotReshare` policy are never included in PEER_HINT frames (already — select_for_share filters) — verify + test; the enumeration guard (limit.rs) is wired at the daemon layer (currently library-only? CHECK call sites and wire it into the control-API dispatch).
- Private mesh (§59): `MeshConfig::local_mesh()` exists — add the membership secret option: `mesh_secret: Option<String>` config; when set, PEER_HINT frames within the mesh are authenticated with an HMAC over the mesh secret (SANCTIONED provisional — document); a node without the secret cannot enumerate the mesh.
- Tests: private candidates never leave the node; enumeration guard fires in the dispatch path; mesh-secret hint validation.

### Task K5: P2 — layered private routing (onion encoding)
- `crates/umc-relay/src/onion.rs` (SANCTIONED): the layered-encryption encoding (privacy.md §10-12): `build_privacy_route(hop_keys: &[[u8;32]], next_hops: &[Vec<u8>], destination_context: &[u8]) -> Vec<u8>` — the payload is wrapped from the innermost layer out: `L3 = seal(dest_context)`, `L2 = seal(L3 || next_hop_2 || route_id_2 || expiry)`, `L1 = seal(L2 || next_hop_1 || route_id_1 || expiry)` (each layer with an independent key — compromise of one hop reveals only the next). `unwrap_privacy_layer(key, layer) -> Result<(Vec<u8>, Option<Vec<u8>>), String>` — the next-hop or None at the destination.
- Tests: 3-hop build → each hop unwraps exactly one layer (assert hop 1 cannot read past layer 2); wrong key fails; route-local ids are opaque (no endpoint identities in the layers).

### Task K6: P2 — direct-path prohibition and route privacy wiring
- `Session` gains `direct_path_allowed: bool` (config-adjacent; P2 sessions set false): the daemon's migration/path logic refuses to use a direct path when false (the add_path/migrate_to paths error or no-op — choose error with a documented `PathPolicy` SessionError variant).
- The relay service's circuit state is already minimal/opaque (circuit ids, no routes) — audit + document (privacy.md §45-46); hop diversity preference: the route cache's candidate selection prefers diverse carriers when available (score adjustment SANCTIONED small: a `diversity` term in score_local_first-adjacent scoring).
- Tests: P2 session refuses a direct-path migration; relay circuit state exposes no endpoint ids.

### Task K7: P3 — traffic padding and timing hygiene
- `NodeConfig` gains `traffic_padding: bool` (default false — opt-in §70): when enabled, the daemon pads outbound data packets to a fixed size (the session's build path appends PADDING frames to reach the profile size — the wire parser handles padding; pick the profile size as the largest recent packet, capped at MTU; SANCTIONED simple scheme, documented); `traffic_padding_active` exposed via the privacy info.
- Clock privacy (§69): audit the wire for precise wall-clock transmission — the bundle metadata uses wall-clock epoch internally (B3) but is it TRANSMITTED on the wire? The BUNDLE frame carries expires_at (relative — check); the handshake carries no wall-clock ✓. Document the audit result; coarse only.
- Tests: with padding on, outbound packet sizes are uniform for data traffic; with padding off, unchanged.

### Task K8: Application visibility and process closure
- `Session::privacy_info()` returns `{ requested_profile, effective_profile, direct_path_allowed, traffic_padding_active, hop_count (1 for direct, relay hops for private routes) }` — the daemon's control API gains `PrivacyService.GetSessionPrivacy` (or folds into GetSession — SANCTIONED whichever is cleaner); applications never receive raw route topology (§57).
- Process (privacy.md §63-65): `spec/decisions.md` gains the privacy-review entry (the P0-P3 ladder status, the K5 onion scheme, the mesh-secret scheme, metadata classification of the wire fields — one table listing PUBLIC/PEER/ROUTE/SESSION/SECRET for the sensitive fields); `docs/PRIVACY.md` summarizing the implemented profile ladder + the documented non-goals (§71).
- Tests: the privacy_info shape; the control API handler.

### Task K9: Phase K gate
- Workspace gate (fmt/clippy/test). Note explicitly in the gate commit: P2 rendezvous/introduction points/replicas and P3 cover traffic/anonymous credentials remain future work (§77), documented in docs/PRIVACY.md.
