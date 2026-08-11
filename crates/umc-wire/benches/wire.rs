use criterion::{black_box, criterion_group, criterion_main, Criterion};
use umc_wire::header::ShortPacketSpace;
use umc_wire::packet::{parse_payload, PacketContext};
use umc_wire::varint;

fn bench_varint(c: &mut Criterion) {
    c.bench_function("varint_encode", |b| {
        b.iter(|| varint::encode(black_box(1_073_741_824)).expect("canonical varint"));
    });
    c.bench_function("varint_decode", |b| {
        let encoded = varint::encode(1_073_741_824).expect("canonical varint");
        b.iter(|| varint::decode(black_box(&encoded)).expect("canonical varint"));
    });
}

fn bench_packet_parse(c: &mut Criterion) {
    // A protected payload containing a PING frame is the smallest valid
    // packet-context parse and exercises frame dispatch plus varint decoding.
    let payload = [0x04u8];
    let context = PacketContext::Protected(ShortPacketSpace::SessionData);
    c.bench_function("protected_packet_parse", |b| {
        b.iter(|| parse_payload(black_box(&context), black_box(&payload)).expect("valid packet"));
    });
}

criterion_group!(wire_benches, bench_varint, bench_packet_parse);
criterion_main!(wire_benches);
