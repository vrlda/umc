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
    Unauthenticated,
    StoreForwardNotAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub destination_hint: Vec<u8>,
    pub peer: Vec<u8>,
    pub expires_at: Instant,
    pub authenticated: bool,
    pub store_forward_allowed: bool,
    pub local_scope_only: bool,
}

#[derive(Debug, Clone)]
pub struct ForwardResult {
    pub id: [u8; 32],
    pub payload: Vec<u8>,
    pub peer: Vec<u8>,
}

/// Select a bundle for handoff on a contact (bundles.md §17.2).
///
/// # Errors
///
/// The selector always succeeds; the returned vector is empty when no
/// eligible bundle matches the contact.
pub fn select_for_contact<'a>(
    manager: &'a BundleManager,
    contact: &Contact,
    now: Instant,
) -> Result<Vec<&'a crate::manager::BundleRecord>, ForwardError> {
    let records: Vec<_> = manager
        .records_iter()
        .filter(|_| contact.authenticated && contact.store_forward_allowed)
        .filter(|_| contact.expires_at > now)
        .filter(|r| r.destination_hint == contact.destination_hint)
        .filter(|r| r.expires_at > now)
        .filter(|r| {
            matches!(
                r.status,
                BundleStatus::Received | BundleStatus::CustodyAccepted
            )
        })
        .filter(|r| !r.do_not_replicate)
        .filter(|r| !r.local_scope_only || contact.local_scope_only)
        .filter(|r| r.replication_count < r.replication_limit)
        .collect();
    Ok(records)
}

/// Perform the handoff: bump replication count, mark Forwarded (bundles.md §16).
///
/// # Errors
///
/// Returns `ForwardError::NotFound` for an unknown ID and
/// `ForwardError::ReplicationLimit` when the handoff would exceed the
/// bundle's stored replication limit.
pub fn handoff(
    manager: &mut BundleManager,
    id: &[u8; 32],
    peer: &[u8],
) -> Result<ForwardResult, ForwardError> {
    let record = manager.record(id).ok_or(ForwardError::NotFound)?;
    if record.do_not_replicate {
        return Err(ForwardError::DoNotReplicate);
    }
    let payload = manager
        .get_payload(id)
        .map_err(|_| ForwardError::NotFound)?;
    manager.mark_forwarded(id).map_err(|error| match error {
        crate::manager::BundleError::ReplicationLimit => ForwardError::ReplicationLimit,
        _ => ForwardError::NotFound,
    })?;
    Ok(ForwardResult {
        id: *id,
        payload,
        peer: peer.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{BundleManager, DEFAULT_LIFETIME_MS};
    use std::sync::atomic::{AtomicU64, Ordering};
    use umc_storage::objects::ObjectStore;
    use umc_storage::quota::{Profile, QuotaAccount};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn manager() -> BundleManager {
        let dir = std::env::temp_dir().join(format!(
            "umc-forward-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        BundleManager::new(
            ObjectStore::open(dir).unwrap(),
            QuotaAccount::new(Profile::Standard, 0, 1_048_576),
        )
    }

    #[test]
    fn forward_on_matching_contact() {
        let mut m = manager();
        let id = m
            .admit(
                b"payload",
                b"s",
                b"dest-hint",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                Instant(0),
            )
            .unwrap();
        let contact = Contact {
            destination_hint: b"dest-hint".to_vec(),
            peer: b"peer-b".to_vec(),
            expires_at: Instant(u64::MAX),
            authenticated: true,
            store_forward_allowed: true,
            local_scope_only: false,
        };
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
        m.admit(
            b"payload",
            b"s",
            b"dest-hint",
            1,
            DEFAULT_LIFETIME_MS,
            3,
            false,
            Instant(0),
        )
        .unwrap();
        let contact = Contact {
            destination_hint: b"other-hint".to_vec(),
            peer: b"p".to_vec(),
            expires_at: Instant(u64::MAX),
            authenticated: true,
            store_forward_allowed: true,
            local_scope_only: false,
        };
        assert!(select_for_contact(&m, &contact, Instant(1))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn replication_limit_stops_forwarding() {
        let mut m = manager();
        let id = m
            .admit(
                b"p",
                b"s",
                b"d",
                1,
                DEFAULT_LIFETIME_MS,
                0,
                false,
                Instant(0),
            )
            .unwrap();
        assert_eq!(
            handoff(&mut m, &id, b"peer").unwrap_err(),
            ForwardError::ReplicationLimit
        );
    }

    #[test]
    fn unauthenticated_or_disallowed_contacts_are_not_selected() {
        let mut m = manager();
        m.admit(
            b"payload",
            b"s",
            b"dest-hint",
            1,
            DEFAULT_LIFETIME_MS,
            3,
            false,
            Instant(0),
        )
        .unwrap();
        for (authenticated, store_forward_allowed) in [(false, true), (true, false)] {
            let contact = Contact {
                destination_hint: b"dest-hint".to_vec(),
                peer: b"peer".to_vec(),
                expires_at: Instant(u64::MAX),
                authenticated,
                store_forward_allowed,
                local_scope_only: false,
            };
            assert!(select_for_contact(&m, &contact, Instant(1))
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn expired_contact_and_forwarded_bundle_are_not_selected() {
        let mut m = manager();
        let id = m
            .admit(
                b"payload",
                b"s",
                b"dest-hint",
                1,
                DEFAULT_LIFETIME_MS,
                3,
                false,
                Instant(0),
            )
            .unwrap();
        let expired_contact = Contact {
            destination_hint: b"dest-hint".to_vec(),
            peer: b"peer".to_vec(),
            expires_at: Instant(1),
            authenticated: true,
            store_forward_allowed: true,
            local_scope_only: false,
        };
        assert!(select_for_contact(&m, &expired_contact, Instant(1))
            .unwrap()
            .is_empty());
        m.mark_forwarded(&id).unwrap();
        let live_contact = Contact {
            expires_at: Instant(u64::MAX),
            ..expired_contact
        };
        assert!(select_for_contact(&m, &live_contact, Instant(2))
            .unwrap()
            .is_empty());
    }
}
