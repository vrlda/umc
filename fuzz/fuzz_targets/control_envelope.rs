#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1 << 20 {
        return;
    }
    let _ = umc_control::proto::umc::api::v1::Envelope::decode(data);
    let mut decoder = umc_control::framing::EnvelopeDecoder::default();
    for chunk in data.chunks(3) {
        if decoder.feed(chunk).is_err() {
            break;
        }
    }
});
