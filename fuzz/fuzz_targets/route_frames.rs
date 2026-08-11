#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = umc_wire::frames::routing::RouteRequestFrame::decode(data);
    let _ = umc_wire::frames::routing::RouteResponseFrame::decode(data);
    let _ = umc_wire::frames::routing::RouteErrorFrame::decode(data);
});
