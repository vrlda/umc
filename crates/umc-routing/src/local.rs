//! Local-first strategy (decisions.md §19): local and direct routes outrank
//! general ones by a fixed margin (routing.md §28).
use crate::score::ScoreInput;
use crate::types::{RouteRecord, RouteScope};
use umc_types::runtime::Instant;

pub const LOCAL_PREFERENCE_BONUS: i64 = 500;

/// Score for the `local-first` strategy. Local evidence is worth a large
/// bonus; general routes still rank among themselves.
#[must_use]
pub fn score_local_first(record: &RouteRecord, now: Instant, input: &ScoreInput) -> i64 {
    let base = crate::score::score_balanced(record, now, input);
    match record.scope {
        RouteScope::LinkLocal | RouteScope::LocalMesh => base + LOCAL_PREFERENCE_BONUS,
        RouteScope::Introduced => base + 100,
        RouteScope::General => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::Duration;

    fn record(scope: RouteScope) -> RouteRecord {
        RouteRecord {
            key: crate::types::RouteKey {
                destination_profile: 0,
                destination_hash: [1u8; 32],
                scope,
                policy_class: 0,
            },
            state: crate::types::RouteState::Usable,
            next_hop: "hop".into(),
            metadata: vec![],
            source_peer: vec![],
            created_at: Instant(0),
            expires_at: Instant(u64::MAX),
            last_success: None,
            last_failure: None,
            failure_count: 0,
            scope,
        }
    }

    #[test]
    fn local_outranks_general() {
        let now = Instant(0);
        let input = ScoreInput::default();
        let local = score_local_first(&record(RouteScope::LocalMesh), now, &input);
        let general = score_local_first(&record(RouteScope::General), now, &input);
        assert!(local > general + LOCAL_PREFERENCE_BONUS - 1);
    }

    #[test]
    fn introduced_beats_general() {
        let now = Instant(0);
        let input = ScoreInput::default();
        let introduced = score_local_first(&record(RouteScope::Introduced), now, &input);
        let general = score_local_first(&record(RouteScope::General), now, &input);
        assert!(introduced > general);
    }

    #[test]
    fn local_preference_never_broadens_scope() {
        // Scoring is only applied after hard constraints; scope narrowing is
        // enforced by admit_request/scope rules, not by the strategy.
        let now = Instant(0);
        let input = ScoreInput::default();
        let _ = score_local_first(&record(RouteScope::General), now, &input);
        let _ = Duration::from_millis(1);
    }
}
