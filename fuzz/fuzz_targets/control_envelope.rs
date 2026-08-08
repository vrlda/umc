#![no_main]

use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let _ = umc_control::proto::umc::api::v1::Envelope::decode(data);
});
