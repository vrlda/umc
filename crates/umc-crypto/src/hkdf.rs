use blake2::digest::Digest;
use blake2::Blake2s256;

/// BLAKE2s block size in bytes (RFC 7693), used for HMAC key padding.
const BLOCK_SIZE: usize = 64;

/// RFC 2104 HMAC over BLAKE2s-256.
#[must_use]
fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        key_block[..32].copy_from_slice(&Blake2s256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for (i, (a, b)) in ipad.iter_mut().zip(opad.iter_mut()).enumerate() {
        *a = key_block[i] ^ 0x36;
        *b = key_block[i] ^ 0x5c;
    }
    let mut inner = Blake2s256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

/// RFC 5869 HKDF-Extract with BLAKE2s-256 (handshake.md §7: HKDF-BLAKE2s).
#[must_use]
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac(salt, ikm)
}

/// RFC 5869 HKDF-Expand with BLAKE2s-256.
///
/// # Errors
/// Returns [`HkdfError::LengthOutOfRange`] if `length` exceeds `255 * 32`.
pub fn expand(
    prk: &[u8; 32],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, super::label::HkdfError> {
    if length > 255 * 32 {
        return Err(super::label::HkdfError::LengthOutOfRange);
    }
    let mut out = Vec::with_capacity(length);
    let mut t: Vec<u8> = Vec::new();
    for counter in 1u8..=255 {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);
        let h = hmac(prk, &input);
        let need = (length - out.len()).min(32);
        out.extend_from_slice(&h[..need]);
        if out.len() == length {
            break;
        }
        t = h.to_vec();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_then_expand_is_stable() {
        let prk = extract(b"salt", b"input");
        let a = expand(&prk, b"info", 32).unwrap();
        let b = expand(&prk, b"info", 32).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_salts_differ() {
        let a = extract(b"salt-a", b"input");
        let b = extract(b"salt-b", b"input");
        assert_ne!(a, b);
    }

    #[test]
    fn matches_blake2s_reference_vectors() {
        let expected_hmac: [u8; 32] =
            hex::decode("269307934ce02f47cf30a0e1346a5d22507b62001d247e852f9978977c021934")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(hmac(b"key", b"input"), expected_hmac);
        let expected_prk: [u8; 32] =
            hex::decode("8e87aebd8e26aef5fa05f31e55a5945ed348bb43130e85051253cb231b1da87d")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(extract(b"salt", b"input"), expected_prk);
        assert_eq!(
            expand(&expected_prk, b"info", 42).unwrap(),
            hex::decode(
                "9c4aa9daae0f39533f3ad12b3d09053fc350155e4a6ae5b691a78eed2cc3abdb51bb34070f0cdbbef0da"
            )
            .unwrap()
        );
    }
}
