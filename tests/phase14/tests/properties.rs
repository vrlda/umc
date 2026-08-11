//! Phase-14 property checks for mandatory monotonic/bounded invariants.

use proptest::prelude::*;
use umc_session::flow::FlowControl;
use umc_wire::varint::{decode, encode, MAX_VARINT};

proptest! {
    #[test]
    fn varint_round_trip_any_canonical_value(value: u64) {
        if value <= MAX_VARINT {
            let encoded = encode(value).expect("canonical value");
            let (decoded, width) = decode(&encoded).expect("encoded value");
            prop_assert_eq!((decoded, width), (value, encoded.len()));
        } else {
            prop_assert!(encode(value).is_err());
        }
    }

    #[test]
    fn flow_control_grants_never_decrease(initial: u64, grants: Vec<u64>) {
        let mut flow = FlowControl::new(initial, 16, 16);
        let mut maximum = initial;
        for grant in grants {
            flow.grant_more(grant);
            prop_assert!(flow.max_data_local >= maximum);
            maximum = flow.max_data_local;
        }
    }
}
