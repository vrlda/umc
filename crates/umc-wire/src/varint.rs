pub const MAX_VARINT: u64 = 4_611_686_018_427_387_903;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    ValueTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    NonCanonical,
    InvalidWidth,
    Overflow,
}

/// Appends the canonical varint encoding of `v` to `out`.
///
/// # Errors
///
/// Returns `ValueTooLarge` if `v` exceeds [`MAX_VARINT`].
pub fn encode_into(out: &mut Vec<u8>, v: u64) -> Result<(), EncodeError> {
    if v <= 63 {
        out.push((v & 0x3F) as u8);
    } else if v <= 16_383 {
        out.push(0b0100_0000 | ((v >> 8) & 0x3F) as u8);
        out.push((v & 0xFF) as u8);
    } else if v <= 1_073_741_823 {
        out.push(0b1000_0000 | ((v >> 24) & 0x3F) as u8);
        out.extend_from_slice(&((v & 0x00FF_FFFF) as u32).to_be_bytes()[1..]);
    } else if v <= MAX_VARINT {
        out.push(0b1100_0000 | ((v >> 56) & 0x3F) as u8);
        out.extend_from_slice(&v.to_be_bytes()[1..]);
    } else {
        return Err(EncodeError::ValueTooLarge);
    }
    Ok(())
}

/// Encodes `v` as a canonical varint.
///
/// # Errors
///
/// Returns `ValueTooLarge` if `v` exceeds [`MAX_VARINT`].
pub fn encode(v: u64) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::with_capacity(9);
    encode_into(&mut out, v)?;
    Ok(out)
}

/// Decodes a varint from the start of `buf`, returning the value and its
/// encoded width in bytes.
///
/// # Errors
///
/// Returns `Truncated` if `buf` is too short, `InvalidWidth` if the value
/// does not fit the width that encoded it, and `NonCanonical` if a smaller
/// width was required.
pub fn decode(buf: &[u8]) -> Result<(u64, usize), DecodeError> {
    let first = *buf.first().ok_or(DecodeError::Truncated)?;
    let width = match first >> 6 {
        0 => 1usize,
        1 => 2usize,
        2 => 4usize,
        _ => 8usize,
    };
    if buf.len() < width {
        return Err(DecodeError::Truncated);
    }
    let mut raw = [0u8; 8];
    raw[..width].copy_from_slice(&buf[..width]);
    raw[0] &= 0x3F;
    let v = u64::from_be_bytes(raw) >> ((8 - width) * 8);
    let fits_width = match width {
        1 => v <= 63,
        2 => v <= 16_383,
        4 => v <= 1_073_741_823,
        _ => v <= MAX_VARINT,
    };
    if !fits_width {
        return Err(DecodeError::InvalidWidth);
    }
    match width {
        2 if v <= 63 => return Err(DecodeError::NonCanonical),
        4 if v <= 16_383 => return Err(DecodeError::NonCanonical),
        8 if v <= 1_073_741_823 => return Err(DecodeError::NonCanonical),
        _ => {}
    }
    Ok((v, width))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_round_trips() {
        for v in [
            0u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            MAX_VARINT,
        ] {
            let enc = encode(v).unwrap();
            let (dec, n) = decode(&enc).unwrap();
            assert_eq!((dec, n), (v, enc.len()), "value {v}");
        }
    }

    #[test]
    fn encoding_widths_match_spec() {
        assert_eq!(encode(0).unwrap(), vec![0x00]);
        assert_eq!(encode(63).unwrap(), vec![0x3F]);
        assert_eq!(encode(64).unwrap(), vec![0x40, 0x40]);
        assert_eq!(encode(16_383).unwrap(), vec![0x7F, 0xFF]);
        assert_eq!(
            encode(1_073_741_824).unwrap(),
            vec![0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn rejects_non_canonical_encodings() {
        assert_eq!(
            decode(&[0x40, 0x00]).unwrap_err(),
            DecodeError::NonCanonical
        );
        assert_eq!(
            decode(&[0x80, 0x00, 0x00, 0x00]).unwrap_err(),
            DecodeError::NonCanonical
        );
        assert_eq!(
            decode(&[0xC0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(),
            DecodeError::NonCanonical
        );
    }

    #[test]
    fn rejects_truncated_and_oversized() {
        assert_eq!(decode(&[]).unwrap_err(), DecodeError::Truncated);
        assert_eq!(decode(&[0x40]).unwrap_err(), DecodeError::Truncated);
        assert_eq!(
            encode(MAX_VARINT + 1).unwrap_err(),
            EncodeError::ValueTooLarge
        );
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn round_trip_any_value(v: u64) {
            if v <= MAX_VARINT {
                let enc = encode(v).unwrap();
                let (dec, n) = decode(&enc).unwrap();
                assert_eq!((dec, n), (v, enc.len()));
            } else {
                assert_eq!(encode(v), Err(EncodeError::ValueTooLarge));
            }
        }

        #[test]
        fn decoded_value_fits_its_width(mut buf: Vec<u8>) {
            buf.resize(8, 0);
            let first = buf[0];
            let width = match first >> 6 {
                0 => 1usize,
                1 => 2usize,
                2 => 4usize,
                _ => 8usize,
            };
            if let Ok((v, _)) = decode(&buf[..width]) {
                let max = match width {
                    1 => 63,
                    2 => 16_383,
                    4 => 1_073_741_823,
                    _ => MAX_VARINT,
                };
                prop_assert!(v <= max, "value {v} exceeds width {width} maximum {max}");
            }
        }
    }
}
