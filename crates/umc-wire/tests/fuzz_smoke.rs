//! Deterministic pseudo-fuzzing: feed seeded random buffers through the parser.
//! Runs on stable; never panics on malformed input.
use umc_wire::packet::{parse_payload, PacketContext};
use umc_wire::varint::decode as decode_varint;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_be_bytes();
            for (dst, src) in chunk.iter_mut().zip(v.iter()) {
                *dst = *src;
            }
        }
    }
}

const SEEDS: [u64; 4] = [0xDEAD_BEEF, 0xCAFE_F00D, 42, u64::MAX];

#[test]
fn parser_never_panics_on_random_buffers() {
    for seed in SEEDS {
        let mut rng = XorShift(seed);
        for _ in 0..25_000 {
            let len = (rng.next() % 300) as usize;
            let mut buf = vec![0u8; len];
            rng.fill(&mut buf);
            let _ = decode_varint(&buf);
            let _ = parse_payload(
                &PacketContext::Protected(umc_wire::header::ShortPacketSpace::SessionData),
                &buf,
            );
            let _ = parse_payload(&PacketContext::Initial, &buf);
        }
    }
}

#[test]
#[allow(clippy::large_stack_arrays)]
fn parser_never_panics_on_corpus_edges() {
    // From wire-format.md §79.
    let corpus: &[&[u8]] = &[
        &[],
        &[0x00],
        &[0x08],
        &[0x48],
        &[0x48, 0x01],
        &[0x48, 0x06],
        &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        &[0x10, 0x00, 0xFF],
        &[0x60, 0x01, 0x00],
        &[0x00; 65_536],
    ];
    for buf in corpus {
        let _ = parse_payload(
            &PacketContext::Protected(umc_wire::header::ShortPacketSpace::SessionData),
            buf,
        );
        let _ = parse_payload(&PacketContext::Initial, buf);
    }
}
