use criterion::{black_box, criterion_group, criterion_main, Criterion};
use umc_crypto::aead::PacketKeys;

fn bench_seal_open(c: &mut Criterion) {
    let keys = PacketKeys::from_traffic_secret(&[7u8; 32]).expect("traffic keys");
    let aad = b"benchmark header";
    let plaintext = [0xA5u8; 256];
    let ciphertext = keys.seal(42, aad, &plaintext).expect("sealed packet");

    c.bench_function("packet_seal_256b", |b| {
        b.iter(|| keys.seal(black_box(42), black_box(aad), black_box(&plaintext)));
    });
    c.bench_function("packet_open_256b", |b| {
        b.iter(|| keys.open(black_box(42), black_box(aad), black_box(&ciphertext)));
    });
}

criterion_group!(crypto_benches, bench_seal_open);
criterion_main!(crypto_benches);
