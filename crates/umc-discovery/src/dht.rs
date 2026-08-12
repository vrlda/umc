//! Bounded, signed peer-record overlay for decentralized discovery.
//!
//! The table is deliberately small and local: it is a Kademlia-style routing
//! hint cache, not a global directory. Records are authenticated by the
//! advertising endpoint and expire automatically.

use std::collections::HashMap;
use umc_crypto::signatures::{IdentityKeyPair, IdentityPublicKey, SIGNATURE_LEN};
use umc_types::runtime::Instant;

pub const K_BUCKET_SIZE: usize = 20;
pub const MAX_RECORDS: usize = 2_048;
pub const MAX_LOOKUP_RESULTS: usize = 16;
pub const RECORD_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtRecord {
    pub endpoint_id: [u8; 32],
    pub identity_public_key: [u8; 32],
    pub carrier_type: String,
    pub connection_hint: Vec<u8>,
    pub expires_at: Instant,
    pub sequence: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl DhtRecord {
    #[must_use]
    pub fn sign(
        identity: &IdentityKeyPair,
        carrier_type: String,
        connection_hint: Vec<u8>,
        expires_at: Instant,
        sequence: u64,
    ) -> Self {
        let public = identity.public();
        let endpoint_id = umc_handshake::identity::endpoint_id(&public);
        let mut record = Self {
            endpoint_id,
            identity_public_key: public.0,
            carrier_type,
            connection_hint,
            expires_at,
            sequence,
            signature: [0u8; SIGNATURE_LEN],
        };
        record.signature = identity.sign(&record.signed_bytes());
        record
    }

    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(128 + self.carrier_type.len() + self.connection_hint.len());
        out.extend_from_slice(b"UMP-DHT-RECORD-v1");
        out.extend_from_slice(&self.endpoint_id);
        out.extend_from_slice(&self.identity_public_key);
        out.extend_from_slice(
            &u16::try_from(self.carrier_type.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(self.carrier_type.as_bytes());
        out.extend_from_slice(
            &u16::try_from(self.connection_hint.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.connection_hint);
        out.extend_from_slice(&self.expires_at.0.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out
    }

    #[must_use]
    pub fn verify(&self, now: Instant) -> bool {
        if self.expires_at <= now
            || self.carrier_type.len() > 64
            || self.connection_hint.len() > 1_024
        {
            return false;
        }
        let public = IdentityPublicKey(self.identity_public_key);
        umc_handshake::identity::endpoint_id(&public) == self.endpoint_id
            && public.verify(&self.signed_bytes(), &self.signature)
    }
}

#[derive(Debug, Default, Clone)]
pub struct DhtTable {
    records: HashMap<([u8; 32], String, Vec<u8>), DhtRecord>,
}

impl DhtTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, record: DhtRecord, now: Instant) -> bool {
        if !record.verify(now) {
            return false;
        }
        let key = (
            record.endpoint_id,
            record.carrier_type.clone(),
            record.connection_hint.clone(),
        );
        if let Some(existing) = self.records.get(&key) {
            if existing.sequence >= record.sequence {
                return false;
            }
        } else if self.records.len() >= MAX_RECORDS {
            self.evict_expired(now);
            if self.records.len() >= MAX_RECORDS {
                return false;
            }
        }
        self.records.insert(key, record);
        true
    }

    pub fn evict_expired(&mut self, now: Instant) {
        self.records.retain(|_, record| record.expires_at > now);
    }

    #[must_use]
    pub fn closest(&self, target: &[u8; 32], maximum: usize, now: Instant) -> Vec<DhtRecord> {
        let mut records: Vec<_> = self
            .records
            .values()
            .filter(|record| record.verify(now))
            .cloned()
            .collect();
        records.sort_by_key(|record| xor_distance(&record.endpoint_id, target));
        records.truncate(maximum.min(MAX_LOOKUP_RESULTS));
        records
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[must_use]
pub fn xor_distance(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    std::array::from_fn(|index| left[index] ^ right[index])
}

#[must_use]
pub fn lookup_plan(
    records: &[DhtRecord],
    target: &[u8; 32],
    maximum: usize,
    now: Instant,
) -> Vec<DhtRecord> {
    let mut plan: Vec<_> = records
        .iter()
        .filter(|record| record.verify(now))
        .cloned()
        .collect();
    plan.sort_by_key(|record| xor_distance(&record.endpoint_id, target));
    plan.truncate(maximum.min(MAX_LOOKUP_RESULTS));
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seed: u8, expires: u64) -> DhtRecord {
        let identity = IdentityKeyPair::from_seed([seed; 32]);
        DhtRecord::sign(
            &identity,
            "ump.tcp/1".into(),
            format!("node-{seed}.example:9001").into_bytes(),
            Instant(expires),
            1,
        )
    }

    #[test]
    fn signed_record_rejects_tampering_and_expiry() {
        let mut signed_record = record(1, 100);
        assert!(signed_record.verify(Instant(99)));
        signed_record.connection_hint.push(0);
        assert!(!signed_record.verify(Instant(99)));
        let expired_record = record(1, 100);
        assert!(!expired_record.verify(Instant(100)));
    }

    #[test]
    fn table_returns_xor_closest_records_and_refreshes_sequences() {
        let mut table = DhtTable::new();
        let first = record(1, 1000);
        let mut newer = first.clone();
        newer.sequence = 2;
        newer.signature = IdentityKeyPair::from_seed([1; 32]).sign(&newer.signed_bytes());
        assert!(table.insert(first.clone(), Instant(0)));
        assert!(!table.insert(first, Instant(0)));
        assert!(table.insert(newer, Instant(0)));
        assert_eq!(table.closest(&[0; 32], 3, Instant(0)).len(), 1);
    }

    #[test]
    fn lookup_plan_is_bounded_and_expired_records_are_excluded() {
        let records = vec![record(1, 100), record(2, 0)];
        let plan = lookup_plan(&records, &[0; 32], 99, Instant(1));
        assert_eq!(plan.len(), 1);
        assert!(plan[0].verify(Instant(1)));
    }
}
