#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = umc_wire::frames::bundle::BundleFrame::decode(data);
});
