//! Property tests for the canonical varint codec (wire-format §14):
//! encode/decode round trips preserve the value and the encoded length is
//! always the canonical width for that value.
use proptest::prelude::*;
use umc_wire::varint::{decode, encode_into, EncodeError, MAX_VARINT};

/// Boundary values at every width transition, plus the overflow edge.
const EDGE_VALUES: [u64; 11] = [
    0,
    1,
    63,
    64,
    16_383,
    16_384,
    (1 << 30) - 1,
    1 << 30,
    (1 << 62) - 1,
    1 << 62,
    u64::MAX,
];

/// The canonical encoded width in bytes for an encodable value.
#[must_use]
fn canonical_width(v: u64) -> usize {
    if v <= 63 {
        1
    } else if v <= 16_383 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

/// Values: uniform random u64, weighted toward the width boundaries.
fn any_varint() -> impl Strategy<Value = u64> {
    prop_oneof![
        4 => any::<u64>(),
        2 => prop::sample::select(&EDGE_VALUES),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn round_trip_preserves_value_and_width(v in any_varint()) {
        let mut enc = Vec::new();
        if v <= MAX_VARINT {
            encode_into(&mut enc, v).unwrap();
            prop_assert_eq!(enc.len(), canonical_width(v), "canonical width for {}", v);
            let (decoded, used) = decode(&enc).unwrap();
            prop_assert_eq!(decoded, v);
            prop_assert_eq!(used, enc.len(), "decode must consume the whole encoding");
        } else {
            prop_assert_eq!(
                encode_into(&mut enc, v),
                Err(EncodeError::ValueTooLarge),
                "values above MAX_VARINT must be rejected"
            );
            prop_assert!(enc.is_empty(), "failed encodes must append nothing");
        }
    }
}
