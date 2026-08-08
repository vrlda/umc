#![no_main]

use libfuzzer_sys::fuzz_target;
use umc_wire::header::ShortPacketSpace;
use umc_wire::packet::{parse_payload, PacketContext};

fuzz_target!(|data: &[u8]| {
    let _ = parse_payload(
        &PacketContext::Protected(ShortPacketSpace::SessionData),
        data,
    );
});
