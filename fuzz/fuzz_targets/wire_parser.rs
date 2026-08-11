#![no_main]
use libfuzzer_sys::fuzz_target;
use umc_wire::header::ShortPacketSpace;
use umc_wire::packet::{parse_payload, PacketContext};

fuzz_target!(|data: &[u8]| {
    // Every packet context: the frame dispatcher and context rules differ
    // per space, so each must be fuzzed.
    let _ = parse_payload(&PacketContext::Protected(ShortPacketSpace::SessionData), data);
    let _ = parse_payload(&PacketContext::Protected(ShortPacketSpace::PathControl), data);
    let _ = parse_payload(&PacketContext::Protected(ShortPacketSpace::RelayData), data);
    let _ = parse_payload(&PacketContext::Initial, data);
    let _ = parse_payload(&PacketContext::Handshake, data);
});
