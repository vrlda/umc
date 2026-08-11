#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TCP and TLS share this bounded stream framing parser in the carrier
    // crate. Exercise both incomplete-prefix and complete-frame paths.
    let _ = umc_carrier::framing::decode_frame(data, 65_535);
    let _ = umc_carrier::framing::read_length(data, 65_535);
    let _ = umc_wire::varint::decode(data);
});
