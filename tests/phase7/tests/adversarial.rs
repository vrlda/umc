//! Phase 7 success criteria: enumeration budgets, endpoint trust, rate
//! limits, the blocklist, and the abuse ledger hold against adversarial
//! input patterns (threat-model.md §49, scenarios 8/12/21).
use std::sync::atomic::{AtomicU64, Ordering};
use umc_core::block::{BlockReason, Blocklist};
use umc_core::rate_limiter::{RateLimitError, RateLimiter};
use umc_core::trust::{TrustLevel, TrustStore};
use umc_discovery::limit::{EnumerationGuard, WINDOW_MS};
use umc_storage::abuse::{AbuseRecord, AbuseStats, AbuseStore, Severity};
use umc_storage::sqlite::SqliteStore;
use umc_types::runtime::Instant;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_store() -> SqliteStore {
    let dir = std::env::temp_dir().join(format!(
        "umc-phase7-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    SqliteStore::open(&dir.join("adversarial.db")).unwrap()
}

#[test]
fn cost_budget_forces_periodic_keepalives() {
    let mut guard = EnumerationGuard::new(10);
    guard.set_step_budget(b"prober", 4);
    // Expensive queries draw 4 from the per-peer budget.
    assert!(guard.step(b"prober", "broadcast", 0));
    assert!(
        !guard.step(b"prober", "query", 0),
        "budget exhausted: probing must be silently dropped"
    );
    // Zero-cost keepalives pass even at the budget edge: the link stays
    // alive while enumeration probing is refused.
    assert!(guard.step(b"prober", "keepalive", 0));
    // The window rolls over, refilling the budget: probing resumes only
    // after the periodic window elapses.
    assert!(guard.step(b"prober", "broadcast", WINDOW_MS));
}

#[test]
fn distrusted_peer_receives_refusals() {
    let store = temp_store();
    let trust = TrustStore::new(&store, TrustLevel::Basic);
    // Unseen peers evaluate to the default: traffic accepted.
    assert_eq!(
        trust.effective_trust_level(b"peer-1").unwrap(),
        TrustLevel::Basic
    );
    // The operator marks the peer distrusted: traffic must be refused.
    trust.mark_distrusted(b"peer-1", 1_000).unwrap();
    assert_eq!(
        trust.effective_trust_level(b"peer-1").unwrap(),
        TrustLevel::Distrusted
    );
    // The refusal is a direct-tooling record, not a report.
    assert!(trust.direct_tooling(b"peer-1").unwrap());
}

#[test]
fn rate_limiter_suppresses_bursts() {
    let mut limiter = RateLimiter::new(100);
    // The steady rule's burst capacity is one tightened second of refill.
    for _ in 0..9 {
        assert_eq!(limiter.check(b"peer-1", 0), Ok(()));
    }
    assert_eq!(
        limiter.check(b"peer-1", 0),
        Err(RateLimitError::RateLimited),
        "bursts beyond capacity must be suppressed"
    );
    // The window replenishes the bucket: sustained traffic passes again.
    assert_eq!(limiter.check(b"peer-1", 1_000), Ok(()));
}

#[test]
fn blocked_endpoint_refused_until_unblocked() {
    let mut list = Blocklist::new(60);
    list.block(b"peer-1", BlockReason::Enumeration, Instant(0));
    assert_eq!(
        list.is_blocked(b"peer-1", Instant(1)),
        Some(Instant(60_000))
    );
    assert_eq!(
        list.reason(b"peer-1", Instant(1)),
        Some(BlockReason::Enumeration)
    );
    // The block lapses at `now + permanence` on its own.
    assert_eq!(list.is_blocked(b"peer-1", Instant(60_000)), None);
    // An operator unblock clears the entry before it would lapse.
    list.block(b"peer-1", BlockReason::Operator, Instant(0));
    assert!(list.is_blocked(b"peer-1", Instant(1)).is_some());
    list.unblock(b"peer-1");
    assert_eq!(list.is_blocked(b"peer-1", Instant(1)), None);
    assert_eq!(list.expiry(b"peer-1"), None);
}

#[test]
fn abuse_records_survive_acknowledgment_cycle() {
    let store = temp_store();
    let abuse = AbuseStore::new(&store);
    let record = AbuseRecord {
        peer_endpoint_id: b"peer-1".to_vec(),
        event_type: "enumeration".into(),
        occurred_at_ms: 1_000,
        severity: Severity::High,
        detail: "query burst".into(),
    };
    let id = abuse.add(record).unwrap();
    assert_eq!(
        abuse.stats().unwrap(),
        AbuseStats {
            total: 1,
            acknowledged: 0,
            open: 1
        }
    );
    abuse.acknowledge(&id).unwrap();
    assert_eq!(
        abuse.stats().unwrap(),
        AbuseStats {
            total: 1,
            acknowledged: 1,
            open: 0
        }
    );
    // The record is still readable after acknowledgement: the ledger keeps
    // the full incident history, not just the open queue.
    let found = abuse.find(&id).unwrap().unwrap();
    assert_eq!(found.peer_endpoint_id, b"peer-1");
    assert_eq!(found.severity, Severity::High);
}
