//! Deterministic pseudo-fuzzing: feed seeded random buffers through the parser.
//! Runs on stable; never panics on malformed input.
use umc_types::frame::FrameType;
use umc_wire::frame::{decode_frames, Frame, FrameError};
use umc_wire::header::ShortPacketSpace;
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
    let mut cases = 0usize;
    for seed in SEEDS {
        let mut rng = XorShift(seed);
        for _ in 0..25_000 {
            cases += 1;
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
    println!(
        "FUZZ_EVIDENCE schema=umc-fuzz-evidence-v1 target=wire_parser seeds={} random_cases={} max_input_bytes=299",
        SEEDS.len(),
        cases
    );
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
            &PacketContext::Protected(ShortPacketSpace::SessionData),
            buf,
        );
        let _ = parse_payload(&PacketContext::Initial, buf);
    }
    println!(
        "FUZZ_EVIDENCE schema=umc-fuzz-evidence-v1 target=wire_parser corpus_edges={}",
        corpus.len()
    );
}

/// Hostile inputs aimed at length-driven slicing: a multi-byte type varint
/// whose body is missing, length-delimited types declaring bodies that are
/// absent, and truncated bodies of every fixed-layout frame that slices by
/// declared length (wire-format §20-22, resource-limits.md §49). Every case
/// must be an `Err` — a panic here is a parser regression.
#[test]
fn hostile_length_inputs_return_errors_never_panic() {
    // BUNDLE (0x60): 2-byte type varint, then a continuation-bit varint
    // where the declared length exceeds every limit.
    assert!(decode_frames(&[0x60, 0xFF, 0xFF]).is_err());
    // Unknown optional length-delimited types (0x3F) with a declared body
    // that is not present in the buffer. Unknown critical types are rejected
    // before their body is interpreted.
    assert_eq!(
        decode_frames(&[0x3F, 0x40, 0x40]),
        Err(FrameError::Truncated)
    );
    assert_eq!(
        decode_frames(&[0x3E, 0x40, 0x40]),
        Err(FrameError::UnknownCriticalFrame(FrameType(0x3E)))
    );
    // Declared-but-absent length of 1 MiB (4-byte varint 0x80 0x10 0x00 0x00).
    assert_eq!(
        decode_frames(&[0x3F, 0x80, 0x10, 0x00, 0x00]),
        Err(FrameError::Truncated)
    );
    // STREAM (0x10) with a declared data length beyond the buffer.
    assert!(decode_frames(&[0x10, 0x00, 0x40, 0x00, 0x40, 0x01]).is_err());
    // ACK (0x08) with a range count far beyond the buffer.
    assert!(decode_frames(&[0x08, 0x00, 0x00, 0x40, 0x40, 0x00]).is_err());
    // DATAGRAM (0x28) with a declared payload length beyond the buffer.
    assert!(decode_frames(&[0x28, 0x00, 0x00, 0x40, 0x40, 0x01]).is_err());
    // The same hostile bodies must never panic at the packet layer either.
    for buf in [
        &[0x60, 0xFF, 0xFF][..],
        &[0x3E, 0x40, 0x40][..],
        &[0x10, 0x00, 0x40, 0x00, 0x40, 0x01][..],
        &[0x08, 0x00, 0x00, 0x40, 0x40, 0x00][..],
        &[0x28, 0x00, 0x00, 0x40, 0x40, 0x01][..],
    ] {
        assert!(parse_payload(
            &PacketContext::Protected(ShortPacketSpace::SessionData),
            buf
        )
        .is_err());
    }
    println!("FUZZ_EVIDENCE schema=umc-fuzz-evidence-v1 target=wire_parser hostile_inputs=7");
}

/// A packet that is pure padding is always acceptable, in any context
/// (wire-format §22): every 0x00 type byte is one PADDING frame.
#[test]
fn pure_padding_packet_accepted() {
    for context in [
        PacketContext::Initial,
        PacketContext::Handshake,
        PacketContext::Protected(ShortPacketSpace::SessionData),
    ] {
        let parsed = parse_payload(&context, &[0x00; 100]).expect("pure padding parses");
        assert!(parsed.frames.iter().all(|f| matches!(f, Frame::Padding)));
    }
}

/// An unknown optional length-delimited frame is self-delimiting: its declared
/// length is consumed and the frames after it still parse (wire-format §21).
#[test]
fn unknown_optional_length_delimited_is_skipped_with_length_consumed() {
    // 0x3F (unknown optional length-delimited), declared body 2 bytes, then
    // 0x04 = PING. The skip must consume exactly the declared body.
    assert_eq!(
        decode_frames(&[0x3F, 0x02, 0xAA, 0xBB, 0x04]).unwrap(),
        vec![Frame::Ping]
    );
    // Two unknown frames back to back, then a known one.
    assert_eq!(
        decode_frames(&[0x3F, 0x01, 0xAA, 0x3F, 0x00, 0x04]).unwrap(),
        vec![Frame::Ping]
    );
}
