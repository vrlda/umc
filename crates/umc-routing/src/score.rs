//! Route scoring (routing.md §22): hard constraints first, then the balanced
//! first-party strategy. Remote metric claims weigh less than local evidence.
use crate::types::RouteRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardConstraint {
    AllowedCarrier(String),
    MaxHops(u64),
    MinTrust(u8),
    LocalOnly,
}

#[derive(Debug, Clone)]
pub struct ScoreInput {
    pub local_success_weight: u64,
}

impl Default for ScoreInput {
    fn default() -> Self {
        Self {
            local_success_weight: 3,
        }
    }
}

/// Score for the `balanced` strategy (decisions.md §19). Higher is better.
#[must_use]
#[allow(clippy::cast_possible_wrap)]
pub fn score_balanced(
    record: &RouteRecord,
    now: umc_types::runtime::Instant,
    input: &ScoreInput,
) -> i64 {
    let mut score: i64 = 0;
    // Freshness.
    let age_ms = now.duration_since(record.created_at).as_millis() as i64;
    score -= age_ms / 10_000;
    // Local evidence outweighs remote claims (routing.md §22.2).
    if let Some(_s) = record.last_success {
        score += 100 * input.local_success_weight as i64;
    }
    if let Some(_f) = record.last_failure {
        score -= 50 * record.failure_count as i64;
    }
    // State ranking.
    score += match record.state {
        crate::types::RouteState::Usable => 200,
        crate::types::RouteState::Candidate => 50,
        crate::types::RouteState::Probing => 30,
        crate::types::RouteState::Degraded => -20,
        crate::types::RouteState::Failed => -200,
        crate::types::RouteState::Expired | crate::types::RouteState::Retired => i64::MIN / 2,
    };
    score
}

/// Filter hard constraints; ineligible candidates never enter scoring
/// (routing.md §22.1).
#[must_use]
#[allow(clippy::naive_bytecount)]
pub fn passes_hard_constraints(record: &RouteRecord, constraints: &[HardConstraint]) -> bool {
    constraints.iter().all(|c| match c {
        HardConstraint::MaxHops(hops) => {
            metadata_u64(&record.metadata, b"hops=").is_some_and(|route_hops| route_hops <= *hops)
        }
        HardConstraint::LocalOnly => record.scope != crate::types::RouteScope::General,
        // Route metadata is an authenticated, bounded policy snapshot. A
        // record without the requested field fails closed; treating missing
        // carrier/trust evidence as a match would turn hard constraints into
        // advisory hints (routing.md §§22.1, 29).
        HardConstraint::AllowedCarrier(carrier) => {
            metadata_value(&record.metadata, b"carrier=") == Some(carrier.as_bytes())
        }
        HardConstraint::MinTrust(minimum) => metadata_u64(&record.metadata, b"trust=")
            .is_some_and(|trust| trust >= u64::from(*minimum)),
    })
}

/// Finds one canonical `key=value` field in route metadata. Metadata is
/// deliberately opaque to the route scorer; producers use NUL-separated
/// bounded fields so arbitrary binary extension fields remain possible.
fn metadata_value<'a>(metadata: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    metadata
        .split(|byte| *byte == 0)
        .find_map(|field| field.strip_prefix(key))
}

fn metadata_u64(metadata: &[u8], key: &[u8]) -> Option<u64> {
    let value = metadata_value(metadata, key)?;
    let value = std::str::from_utf8(value).ok()?;
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::Duration;

    fn usable_record(now: umc_types::runtime::Instant) -> RouteRecord {
        RouteRecord {
            key: crate::types::RouteKey {
                destination_profile: 0,
                destination_hash: [0u8; 32],
                scope: crate::types::RouteScope::LocalMesh,
                policy_class: 0,
            },
            state: crate::types::RouteState::Usable,
            next_hop: "hop".into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: now,
            expires_at: now + Duration::from_millis(600_000),
            last_success: Some(now),
            last_failure: None,
            failure_count: 0,
            scope: crate::types::RouteScope::LocalMesh,
        }
    }

    #[test]
    fn usable_beats_failed() {
        let now = umc_types::runtime::Instant(0);
        let usable = usable_record(now);
        let mut failed = usable.clone();
        failed.state = crate::types::RouteState::Failed;
        assert!(
            score_balanced(&usable, now, &ScoreInput::default())
                > score_balanced(&failed, now, &ScoreInput::default())
        );
    }

    #[test]
    fn failures_penalize() {
        let now = umc_types::runtime::Instant(100_000);
        let fresh = usable_record(now);
        let mut stale = usable_record(now);
        stale.created_at = umc_types::runtime::Instant(0);
        assert!(
            score_balanced(&fresh, now, &ScoreInput::default())
                > score_balanced(&stale, now, &ScoreInput::default())
        );
    }

    #[test]
    fn local_only_constraint_filters_general() {
        let now = umc_types::runtime::Instant(0);
        let mut record = usable_record(now);
        record.scope = crate::types::RouteScope::General;
        assert!(!passes_hard_constraints(
            &record,
            &[HardConstraint::LocalOnly]
        ));
    }

    #[test]
    fn policy_constraints_fail_closed_without_authenticated_metadata() {
        let now = umc_types::runtime::Instant(0);
        let record = usable_record(now);
        assert!(!passes_hard_constraints(
            &record,
            &[HardConstraint::AllowedCarrier("ump.tcp/1".into())]
        ));
        assert!(!passes_hard_constraints(
            &record,
            &[HardConstraint::MinTrust(1)]
        ));
        assert!(!passes_hard_constraints(
            &record,
            &[HardConstraint::MaxHops(2)]
        ));
    }

    #[test]
    fn policy_constraints_read_bounded_metadata_fields() {
        let now = umc_types::runtime::Instant(0);
        let mut record = usable_record(now);
        record.metadata = b"carrier=ump.tcp/1\0trust=4\0hops=2".to_vec();
        assert!(passes_hard_constraints(
            &record,
            &[
                HardConstraint::AllowedCarrier("ump.tcp/1".into()),
                HardConstraint::MinTrust(3),
                HardConstraint::MaxHops(2),
            ]
        ));
        assert!(!passes_hard_constraints(
            &record,
            &[HardConstraint::AllowedCarrier("ump.udp/1".into())]
        ));
        assert!(!passes_hard_constraints(
            &record,
            &[HardConstraint::MaxHops(1)]
        ));
    }
}
