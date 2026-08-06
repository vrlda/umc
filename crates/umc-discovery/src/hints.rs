//! `PEER_HINT` exchange (discovery.md §13, wire-format.md §51).
use crate::provider::{CandidateAuth, CandidateSource, PeerCandidate, SharingPolicy};
use umc_types::runtime::Instant;
use umc_wire::frames::misc::{PeerHintEntry, PeerHintFrame};
use umc_wire::frames::misc::{
    MAX_AUTHENTICATOR, MAX_CARRIER_TYPE, MAX_CONNECTION_HINT, MAX_PEER_ID,
};

pub const MAX_HINTS_PER_FRAME: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HintError {
    TooManyHints,
    ReshareForbidden,
    RateLimited,
    FieldLimit,
}

/// Select hints to share: public, fresh, successful, diverse (discovery.md §13.3).
#[must_use]
pub fn select_for_share(
    candidates: &[PeerCandidate],
    maximum: usize,
    now: Instant,
) -> Vec<PeerCandidate> {
    candidates
        .iter()
        .filter(|c| !c.is_expired(now))
        .filter(|c| {
            c.sharing_policy == SharingPolicy::ShareGeneral
                || c.sharing_policy == SharingPolicy::ShareLocalScope
                || c.sharing_policy == SharingPolicy::ShareSelected
        })
        .take(maximum.min(MAX_HINTS_PER_FRAME))
        .cloned()
        .collect()
}

/// Convert candidates into a `PEER_HINT` frame (wire-format.md §51).
///
/// # Errors
///
/// Returns [`HintError::TooManyHints`] if more than
/// [`MAX_HINTS_PER_FRAME`] candidates are supplied.
pub fn build_peer_hint(candidates: &[PeerCandidate]) -> Result<PeerHintFrame, HintError> {
    if candidates.len() > MAX_HINTS_PER_FRAME {
        return Err(HintError::TooManyHints);
    }
    let entries = candidates
        .iter()
        .map(|c| PeerHintEntry {
            temporary_peer_id: c.candidate_id.to_be_bytes().to_vec(),
            carrier_type: c.carrier_type.clone().into_bytes(),
            connection_hint: c.connection_hint.clone(),
            expiration_time: c.expires_at.0,
            public: c.sharing_policy == SharingPolicy::ShareGeneral,
            introduced: c.authentication == CandidateAuth::IntroductionAuthenticated,
            local: c.local,
            ephemeral: c.source == CandidateSource::LocalDiscovery,
            do_not_reshare: c.sharing_policy == SharingPolicy::DoNotReshare,
            authenticator: Vec::new(),
        })
        .collect();
    Ok(PeerHintFrame { entries })
}

/// Apply received hints: validate limits, preserve policy, respect
/// `DO_NOT_RESHARE` (discovery.md §13.4, threat-model.md §19).
///
/// Every entry field is validated against its wire limit before anything is
/// applied; a frame that violates a limit is rejected wholesale
/// (discovery.md §13.4 "Validate all field limits").
///
/// # Errors
///
/// Returns [`HintError::TooManyHints`] if the frame exceeds
/// [`MAX_HINTS_PER_FRAME`] entries, and [`HintError::FieldLimit`] if any
/// entry field exceeds its wire limit or a temporary peer id is not exactly
/// 8 bytes (it cannot be represented as a candidate id).
pub fn apply_received_hints(
    frame: &PeerHintFrame,
    sender: &[u8],
    now: Instant,
    table: &mut crate::table::CandidateTable,
) -> Result<usize, HintError> {
    if frame.entries.len() > MAX_HINTS_PER_FRAME {
        return Err(HintError::TooManyHints);
    }
    for entry in &frame.entries {
        if entry.temporary_peer_id.len() > MAX_PEER_ID
            || entry.temporary_peer_id.len() != 8
            || entry.carrier_type.len() > MAX_CARRIER_TYPE
            || entry.connection_hint.len() > MAX_CONNECTION_HINT
            || entry.authenticator.len() > MAX_AUTHENTICATOR
        {
            return Err(HintError::FieldLimit);
        }
    }
    let mut accepted = 0;
    for entry in &frame.entries {
        // DO_NOT_RESHARE candidates are accepted locally but never forwarded
        // (discovery.md §9.2); the DoNotReshare policy below keeps them out of
        // later selection.
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&entry.temporary_peer_id);
        let candidate = PeerCandidate {
            candidate_id: u64::from_be_bytes(id_bytes),
            carrier_type: String::from_utf8_lossy(&entry.carrier_type).to_string(),
            connection_hint: entry.connection_hint.clone(),
            source: CandidateSource::PeerHint,
            created_at: now,
            expires_at: Instant(entry.expiration_time),
            sharing_policy: if entry.do_not_reshare {
                SharingPolicy::DoNotReshare
            } else if entry.public {
                SharingPolicy::ShareGeneral
            } else {
                SharingPolicy::LocalUseOnly
            },
            authentication: if entry.introduced {
                CandidateAuth::IntroductionAuthenticated
            } else {
                CandidateAuth::Unauthenticated
            },
            local: entry.local,
        };
        // The sender is intentionally not stored in Phase 3 (discovery.md
        // §13.4); source attribution on the table entry lands with the
        // Phase 14 source_peer field.
        let _ = sender;
        if table.upsert(candidate, now).is_ok() {
            accepted += 1;
        }
    }
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::CandidateTable;

    fn candidate(id: u64, policy: SharingPolicy, expires: u64) -> PeerCandidate {
        PeerCandidate {
            candidate_id: id,
            carrier_type: "ump.udp/1".into(),
            connection_hint: vec![],
            source: CandidateSource::PeerHint,
            created_at: Instant(0),
            expires_at: Instant(expires),
            sharing_policy: policy,
            authentication: CandidateAuth::Unauthenticated,
            local: false,
        }
    }

    fn entry(id: u64, policy: SharingPolicy) -> PeerHintEntry {
        PeerHintEntry {
            temporary_peer_id: id.to_be_bytes().to_vec(),
            carrier_type: b"ump.udp/1".to_vec(),
            connection_hint: vec![],
            expiration_time: u64::MAX,
            public: policy == SharingPolicy::ShareGeneral,
            introduced: false,
            local: false,
            ephemeral: false,
            do_not_reshare: policy == SharingPolicy::DoNotReshare,
            authenticator: vec![],
        }
    }

    #[test]
    fn selection_filters_private_hints() {
        let candidates = vec![
            candidate(1, SharingPolicy::ShareGeneral, u64::MAX),
            candidate(2, SharingPolicy::DoNotReshare, u64::MAX),
            candidate(3, SharingPolicy::LocalUseOnly, u64::MAX),
        ];
        let selected = select_for_share(&candidates, 10, Instant(0));
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].candidate_id, 1);
    }

    #[test]
    fn frame_round_trip_preserves_policy() {
        let c = candidate(7, SharingPolicy::ShareGeneral, u64::MAX);
        let frame = build_peer_hint(&[c]).unwrap();
        assert_eq!(frame.entries.len(), 1);
        assert!(frame.entries[0].public);
        assert!(!frame.entries[0].do_not_reshare);
    }

    #[test]
    fn too_many_hints_rejected() {
        let mut candidates = Vec::new();
        for i in 0..MAX_HINTS_PER_FRAME + 1 {
            candidates.push(candidate(i as u64, SharingPolicy::ShareGeneral, u64::MAX));
        }
        assert_eq!(build_peer_hint(&candidates), Err(HintError::TooManyHints));
    }

    #[test]
    fn field_limits_validated() {
        let mut table = CandidateTable::new(100);
        // A well-formed frame applies.
        let valid = PeerHintFrame {
            entries: vec![entry(5, SharingPolicy::ShareGeneral)],
        };
        assert_eq!(
            apply_received_hints(&valid, b"peer-a", Instant(0), &mut table),
            Ok(1)
        );

        // Oversized connection hint rejects the whole frame.
        let mut oversized = entry(6, SharingPolicy::ShareGeneral);
        oversized.connection_hint = vec![0u8; MAX_CONNECTION_HINT + 1];
        assert_eq!(
            apply_received_hints(
                &PeerHintFrame {
                    entries: vec![oversized]
                },
                b"peer-a",
                Instant(0),
                &mut table
            ),
            Err(HintError::FieldLimit)
        );

        // Bad temporary-peer-id length is rejected, not defaulted.
        let mut bad_id = entry(7, SharingPolicy::ShareGeneral);
        bad_id.temporary_peer_id = vec![1, 2, 3];
        assert_eq!(
            apply_received_hints(
                &PeerHintFrame {
                    entries: vec![bad_id]
                },
                b"peer-a",
                Instant(0),
                &mut table
            ),
            Err(HintError::FieldLimit)
        );

        // Oversized carrier type rejects.
        let mut bad_carrier = entry(8, SharingPolicy::ShareGeneral);
        bad_carrier.carrier_type = vec![0u8; MAX_CARRIER_TYPE + 1];
        assert_eq!(
            apply_received_hints(
                &PeerHintFrame {
                    entries: vec![bad_carrier]
                },
                b"peer-a",
                Instant(0),
                &mut table
            ),
            Err(HintError::FieldLimit)
        );

        // Oversized authenticator rejects.
        let mut bad_auth = entry(9, SharingPolicy::ShareGeneral);
        bad_auth.authenticator = vec![0u8; MAX_AUTHENTICATOR + 1];
        assert_eq!(
            apply_received_hints(
                &PeerHintFrame {
                    entries: vec![bad_auth]
                },
                b"peer-a",
                Instant(0),
                &mut table
            ),
            Err(HintError::FieldLimit)
        );
    }
}
