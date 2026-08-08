//! Phase 13 resource-limit enforcement (resource-limits.md §8-24, §42-52):
//! replay windows, reassembly budgets, datagram queues, and the route cache
//! all stay bounded under volume, without panics.
use umc_crypto::aead::PacketKeys;
use umc_routing::cache::RouteCache;
use umc_routing::types::{RouteKey, RouteRecord, RouteScope, RouteState};
use umc_session::datagram::{
    Datagram, DatagramError, DatagramQueue, MAX_QUEUED_DATAGRAMS, MAX_QUEUED_DATAGRAM_BYTES,
};
use umc_session::packet::build_protected_packet;
use umc_session::session::{Role, Session, SessionConfig};
use umc_session::spaces::PacketSpace;
use umc_session::stream::{Stream, StreamError, MAX_OUT_OF_ORDER_BYTES, MAX_OUT_OF_ORDER_RANGES};
use umc_types::runtime::{Clock, Duration, Instant};
use umc_wire::header::ShortPacketSpace;

#[derive(Debug)]
struct FakeClock(Instant);

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.0
    }
}

fn session() -> Session {
    let config = SessionConfig {
        role: Role::Server,
        dcid: vec![7u8; 8],
        local_traffic_secret: [1u8; 32],
        remote_traffic_secret: [2u8; 32],
        initial_max_data: 1 << 20,
        initial_max_stream_data: 1 << 16,
        max_ack_delay_ms: 25,
    };
    Session::new(config, &FakeClock(Instant(0))).unwrap()
}

#[test]
fn replay_window_memory_bounded() {
    // 100k unique sequential packets through a real Session: the 16-bit
    // truncated packet numbers wrap the 4096-bit ring many times, but the
    // window stays a fixed 512 bytes and nothing panics.
    let mut session = session();
    let keys = PacketKeys::from_traffic_secret(&[2u8; 32]).unwrap();
    let dcid = vec![7u8; 8];
    let payload = [0x04]; // PING
    for pn in 0..100_000u64 {
        // The AEAD nonce is derived from the truncated wire pn; admission
        // reconstructs the full pn from the same 16-bit value.
        let wire_pn = pn & 0xFFFF;
        let pkt = build_protected_packet(
            &keys,
            &umc_crypto::header_protection::header_protection_key(&[2u8; 32]),
            ShortPacketSpace::SessionData,
            &dcid,
            0,
            wire_pn,
            false,
            &payload,
        )
        .unwrap();
        session.on_inbound(Instant(0), &pkt).unwrap();
    }
    assert_eq!(
        session.replay_bytes(PacketSpace::SessionData),
        Some(512),
        "4096-bit window must stay 512 bytes regardless of traffic volume"
    );
}

#[test]
fn stream_reassembly_budget_enforced() {
    // 300 sparse 4 KiB ranges: the 257th must be refused and the buffered
    // bytes must never exceed the out-of-order cap.
    let mut stream = Stream::new(0, Vec::new(), u64::MAX);
    let chunk = vec![0xAAu8; 4096];
    for i in 0..MAX_OUT_OF_ORDER_RANGES as u64 {
        stream
            .receive(i * 8192, &chunk, false)
            .unwrap_or_else(|e| panic!("range {i} must buffer: {e:?}"));
    }
    assert_eq!(stream.buffered_bytes, MAX_OUT_OF_ORDER_BYTES);
    assert_eq!(
        stream.receive(MAX_OUT_OF_ORDER_RANGES as u64 * 8192, &chunk, false),
        Err(StreamError::OutOfOrderBudgetExceeded)
    );
    assert!(
        stream.buffered_bytes <= MAX_OUT_OF_ORDER_BYTES,
        "rejected input must not grow the buffered byte count"
    );
}

#[test]
fn datagram_queue_bounded() {
    // 300 datagrams of 8 KiB: the queue must refuse before count or bytes
    // exceed their caps, keeping memory under 2 MiB.
    let mut queue = DatagramQueue::new();
    let data = vec![0u8; 8 * 1024];
    let mut accepted = 0usize;
    for _ in 0..300 {
        let d = Datagram {
            context_id: 0,
            data: data.clone(),
            expires_at_ms: None,
            ack_requested: false,
        };
        match queue.enqueue_outbound(d, 8 * 1024) {
            Ok(()) => accepted += 1,
            Err(DatagramError::QueueFull | DatagramError::BytesFull) => break,
            Err(other) => panic!("unexpected queue error: {other:?}"),
        }
    }
    assert!(
        accepted < 300,
        "queue accepted all 300 datagrams; no bound enforced"
    );
    assert!(
        accepted <= MAX_QUEUED_DATAGRAMS && accepted * 8 * 1024 <= MAX_QUEUED_DATAGRAM_BYTES,
        "queue allowed {accepted} x 8 KiB, past the {MAX_QUEUED_DATAGRAMS}-item / \
         {MAX_QUEUED_DATAGRAM_BYTES}-byte caps"
    );
}

#[test]
fn route_cache_evicts_expired() {
    // 10k records with 1 ms lifetimes: after the clock advances, every
    // scan is empty (no expired record is ever returned) and the cache
    // fully drains.
    let now = Instant(0);
    let lifetime = Duration::from_millis(1);
    let mut cache = RouteCache::new(3, lifetime);
    for i in 0..10_000u16 {
        let mut hash = [0u8; 32];
        hash[..2].copy_from_slice(&i.to_le_bytes());
        let key = RouteKey {
            destination_profile: 0,
            destination_hash: hash,
            scope: RouteScope::General,
            policy_class: 0,
        };
        let record = RouteRecord {
            key: key.clone(),
            state: RouteState::Usable,
            next_hop: format!("hop-{i}"),
            metadata: Vec::new(),
            source_peer: Vec::new(),
            created_at: now,
            expires_at: now + lifetime,
            last_success: None,
            last_failure: None,
            failure_count: 0,
            scope: RouteScope::General,
        };
        cache.insert(record, now);
    }
    assert_eq!(cache.len(), 10_000);
    let later = now + Duration::from_millis(2);
    cache.evict_expired(later);
    assert_eq!(
        cache.len(),
        0,
        "all 1 ms records must be expired after 2 ms"
    );
    let key = RouteKey {
        destination_profile: 0,
        destination_hash: [7u8; 32],
        scope: RouteScope::General,
        policy_class: 0,
    };
    assert!(
        cache.candidates(&key, later).is_empty(),
        "scans must never return expired records"
    );
}
