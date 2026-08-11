//! Phase 6 success criterion: a bundle created while the destination is
//! unreachable is delivered when connectivity returns.
use std::sync::atomic::{AtomicU64, Ordering};
use umc_bundle::envelope::{open_bundle, seal_bundle};
use umc_bundle::expiry::evict_expired;
use umc_bundle::forward::{handoff, select_for_contact, Contact};
use umc_bundle::id::bundle_id;
use umc_bundle::manager::{BundleManager, BundleStatus, DEFAULT_LIFETIME_MS};
use umc_crypto::signatures::StaticHandshakeKeyPair;
use umc_storage::objects::ObjectStore;
use umc_storage::quota::{Profile, QuotaAccount};
use umc_types::runtime::{Duration, Instant};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn manager() -> BundleManager {
    let dir = std::env::temp_dir().join(format!(
        "umc-phase6-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    BundleManager::new(
        ObjectStore::open(dir).unwrap(),
        QuotaAccount::new(Profile::Standard, 0, 16 * 1024 * 1024),
    )
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
    let admitted = store
        .admit(
            &envelope.encrypted_payload,
            b"sender",
            destination_hint,
            1,
            DEFAULT_LIFETIME_MS,
            3,
            false,
            now,
        )
        .unwrap();
    assert_eq!(admitted, id, "bundle ID is content-derived and stable");
    assert_eq!(store.record(&id).unwrap().status, BundleStatus::Received);

    // 3. Disconnection: time passes, the bundle is still valid but unforwarded.
    let mid = now + Duration::from_millis(60_000);
    assert_eq!(evict_expired(&mut store, mid), 0);

    // 4. Connectivity returns: a contact for the destination appears.
    let contact = Contact {
        destination_hint: destination_hint.to_vec(),
        peer: b"destination-adjacent".to_vec(),
        expires_at: mid + Duration::from_millis(30_000),
    };
    let selected = select_for_contact(&store, &contact, mid).unwrap();
    assert_eq!(selected.len(), 1);

    // 5. Handoff; the destination-facing node opens the envelope.
    let result = handoff(&mut store, &id, b"destination-adjacent").unwrap();
    let opened = open_bundle(&destination, &envelope).unwrap();
    assert_eq!(opened, b"delayed message");
    assert_eq!(
        result.payload, envelope.encrypted_payload,
        "storage node forwards ciphertext, never plaintext"
    );
    assert_eq!(store.record(&id).unwrap().status, BundleStatus::Forwarded);
}

#[test]
fn bundle_survives_longer_than_any_session() {
    // Bundles outlive live sessions by design (bundles.md §21.1).
    let mut store = manager();
    let id = store
        .admit(
            b"persist me",
            b"s",
            b"d",
            1,
            DEFAULT_LIFETIME_MS,
            3,
            false,
            Instant(0),
        )
        .unwrap();
    // A live session would have timed out (max 30s idle per session.md); the
    // bundle is still stored an hour later.
    assert_eq!(evict_expired(&mut store, Instant(3_600_000)), 0);
    assert!(store.get_payload(&id).is_ok());
}
