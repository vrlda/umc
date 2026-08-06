//! Property tests for the replay window (session.md §8.2): an admit stream
//! with 16-bit-truncated packet numbers never admits the same pn twice and
//! never admits a pn below the retained window.
use proptest::prelude::*;
use std::collections::HashSet;
use umc_session::spaces::{PacketSpace, PacketSpaceState, DEFAULT_REPLAY_WINDOW};

/// Up to 200 packet numbers spanning several 4096-wide replay windows: the
/// range stays below the 16-bit reconstruction half-window (2^15), so every
/// truncated value recovers exactly, while reordered sequences push early
/// packets below the retained window and force genuine rejections.
fn random_pns() -> impl Strategy<Value = Vec<u64>> {
    prop::collection::vec(0..16_384u64, 0..200)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn admits_are_unique_and_never_below_window(pns in random_pns()) {
        let mut space = PacketSpaceState::new(PacketSpace::SessionData);
        let mut admitted = HashSet::new();
        for pn in pns {
            let truncated = pn & 0xFFFF; // 16-bit truncation
            if let Ok(admitted_pn) = space.admit_received(truncated, 16) {
                // (a) The same pn is never admitted twice.
                prop_assert!(
                    admitted.insert(admitted_pn),
                    "pn {admitted_pn} admitted twice"
                );
                // (b) The admitted pn lies within [largest - 4096, largest].
                let largest = space.largest_received();
                prop_assert!(
                    admitted_pn <= largest
                        && admitted_pn + DEFAULT_REPLAY_WINDOW > largest,
                    "admitted {admitted_pn} outside [largest-4096, largest] = [{}, {}]",
                    largest.saturating_sub(DEFAULT_REPLAY_WINDOW),
                    largest,
                );
            }
        }
    }

    #[test]
    fn monotonic_sequence_admits_every_distinct_pn(mut sorted in random_pns()) {
        sorted.sort_unstable();
        sorted.dedup();
        let expected = sorted.last().copied().map_or(0, |max_offset| max_offset);
        let mut space = PacketSpaceState::new(PacketSpace::SessionData);
        for pn in sorted {
            let truncated = pn & 0xFFFF;
            prop_assert!(
                space.admit_received(truncated, 16).is_ok(),
                "pn {pn} must be admitted in monotonic order"
            );
        }
        prop_assert_eq!(space.largest_received(), expected);
    }
}
