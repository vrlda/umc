#![no_main]
use libfuzzer_sys::fuzz_target;
use umc_wire::frames::relay::{RelayCloseFrame, RelayDataFrame, RelayOpenFrame, RelayStatusFrame};
use umc_wire::header::ShortPacketSpace;
use umc_wire::packet::{parse_payload, PacketContext};

// The relay crate has no standalone byte parser: relay frames live in
// umc-wire (frames/relay.rs) and are dispatched from protected payloads,
// so this target feeds raw bytes through every relay frame decoder plus
// the RelayData packet context.
fuzz_target!(|data: &[u8]| {
    let _ = RelayOpenFrame::decode(data);
    let _ = RelayStatusFrame::decode(data);
    let _ = RelayDataFrame::decode(data);
    let _ = RelayCloseFrame::decode(data);
    let _ = parse_payload(&PacketContext::Protected(ShortPacketSpace::RelayData), data);
});
