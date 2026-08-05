//! Official interop vectors (wire-format.md §78).
use umc_wire::header::{HeaderByte, LongHeader, LongPacketType, ShortHeader, ShortPacketSpace};
use umc_wire::pn::reconstruct;
use umc_wire::varint::{decode, encode};

#[test]
fn varint_vectors() {
    let cases: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (63, &[0x3F]),
        (64, &[0x40, 0x40]),
        (16_383, &[0x7F, 0xFF]),
        // 2^14 = 16384: 4-byte width, prefix byte 0x80, low 3 bytes 00 40 00.
        (16_384, &[0x80, 0x00, 0x40, 0x00]),
        (1_073_741_823, &[0xBF, 0xFF, 0xFF, 0xFF]),
        // 2^30 = 1073741824: exceeds the 4-byte width maximum (2^30 - 1),
        // MUST use the 8-byte width.
        (
            1_073_741_824,
            &[0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
        ),
        (
            4_611_686_018_427_387_903,
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        ),
    ];
    for (v, expected) in cases {
        assert_eq!(&encode(*v).unwrap(), expected, "encode {v}");
        assert_eq!(decode(expected).unwrap().0, *v, "decode {v}");
    }
}

#[test]
fn packet_number_vectors() {
    assert_eq!(reconstruct(100, 8, 101).unwrap(), 100);
    assert_eq!(reconstruct(1, 8, 255).unwrap(), 257);
    assert_eq!(reconstruct(200, 8, 400).unwrap(), 456);
}

#[test]
fn header_byte_vectors() {
    assert_eq!(HeaderByte::LONG_INITIAL.encode(), 0b1000_0000);
    assert_eq!(HeaderByte::SHORT_SESSION.encode(), 0b0000_0000);
    assert_eq!(HeaderByte::decode(0b1000_0100).unwrap().pn_bits, 16);
}

#[test]
fn long_header_vector() {
    let h = LongHeader {
        ptype: LongPacketType::Initial,
        version: 1,
        dcid: vec![0x11; 8],
        scid: vec![0x22; 8],
        token: vec![],
        payload_len: 64,
        packet_number: 4021,
        pn_bits: 16,
    };
    let enc = h.encode().unwrap();
    assert_eq!(enc[0], 0b1000_0000);
    assert_eq!(&enc[1..5], &[0, 0, 0, 1]);
    assert_eq!(enc[5], 8);
    assert_eq!(&enc[6..14], &[0x11; 8]);
    assert_eq!(enc[14], 8);
    assert_eq!(&enc[15..23], &[0x22; 8]);
    assert_eq!(enc[23], 0x00, "token length 0");
    // Payload length 64 is a 2-byte varint: 0x40 0x40.
    assert_eq!(&enc[24..26], &[0x40, 0x40]);
    // Packet number 4021 as 2 bytes: 0x0F 0xB5.
    assert_eq!(&enc[26..], &[0x0F, 0xB5]);
}

#[test]
fn short_header_vector() {
    let h = ShortHeader {
        space: ShortPacketSpace::SessionData,
        dcid: vec![0x33; 8],
        path_id: 1,
        packet_number: 4021,
        pn_bits: 16,
        key_phase: false,
    };
    let enc = h.encode().unwrap();
    // P field = 01 (2-byte packet number): 0b0000_0100.
    assert_eq!(enc[0], 0b0000_0100);
    assert_eq!(&enc[1..9], &[0x33; 8]);
    assert_eq!(&enc[9..], &[0x01, 0x0F, 0xB5]);
}
