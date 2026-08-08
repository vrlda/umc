//! Layered private-route encoding (privacy.md §10–12).
//!
//! Each hop can open exactly one authenticated layer. The layer exposes an
//! opaque next-hop descriptor and the still-encrypted inner layer; the final
//! hop receives only the destination context. Route metadata is intentionally
//! caller-supplied and is never interpreted as an endpoint identity here.

use umc_crypto::aead::PacketKeys;

const VERSION: u8 = 1;
const TERMINAL: u8 = 0;
const FORWARD: u8 = 1;
const MAX_FIELD: usize = 65_535;
const AAD: &[u8] = b"UMP-PRIVACY-ROUTE-v1";

/// Builds an onion route from the destination inward to the first hop.
///
/// `hop_keys` contains one independent 32-byte traffic secret per hop. The
/// `next_hops` list contains one opaque forwarding descriptor for every
/// transition, so it must have exactly `hop_keys.len() - 1` entries. The
/// destination context is carried only in the terminal layer.
///
/// # Errors
///
/// Returns a message when the hop/descriptor counts are inconsistent, a
/// field exceeds the bounded layer size, or authenticated encryption fails.
pub fn build_privacy_route(
    hop_keys: &[[u8; 32]],
    next_hops: &[Vec<u8>],
    destination_context: &[u8],
) -> Result<Vec<u8>, String> {
    if hop_keys.is_empty() {
        return Err("privacy route needs at least one hop".into());
    }
    if next_hops.len() != hop_keys.len().saturating_sub(1) {
        return Err("privacy route needs one descriptor per hop transition".into());
    }
    if destination_context.len() > MAX_FIELD {
        return Err("destination context exceeds privacy-route bound".into());
    }

    let terminal = encode_terminal(destination_context)?;
    let mut layer = seal_layer(&hop_keys[hop_keys.len() - 1], &terminal)?;
    for (index, descriptor) in next_hops.iter().enumerate().rev() {
        if descriptor.len() > MAX_FIELD {
            return Err("next-hop descriptor exceeds privacy-route bound".into());
        }
        let plaintext = encode_forward(descriptor, &layer)?;
        layer = seal_layer(&hop_keys[index], &plaintext)?;
    }
    Ok(layer)
}

/// Opens one privacy-route layer.
///
/// The returned bytes are either the encrypted inner layer (when `next_hop`
/// is `Some`) or the destination context (when it is `None`). A wrong key,
/// malformed layer, or trailing bytes is rejected.
///
/// # Errors
///
/// Returns a message when authentication or bounded layer decoding fails.
pub fn unwrap_privacy_layer(
    key: &[u8; 32],
    layer: &[u8],
) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
    let plaintext = open_layer(key, layer)?;
    let (version, kind, mut rest) = plaintext
        .get(..2)
        .map(|prefix| (prefix[0], prefix[1], &plaintext[2..]))
        .ok_or_else(|| "privacy layer truncated".to_string())?;
    if version != VERSION {
        return Err("unsupported privacy layer version".into());
    }
    match kind {
        TERMINAL => {
            let destination = decode_field(&mut rest)?;
            if !rest.is_empty() {
                return Err("privacy terminal has trailing bytes".into());
            }
            Ok((destination, None))
        }
        FORWARD => {
            let descriptor = decode_field(&mut rest)?;
            let inner = decode_field(&mut rest)?;
            if !rest.is_empty() {
                return Err("privacy forward layer has trailing bytes".into());
            }
            Ok((inner, Some(descriptor)))
        }
        _ => Err("unknown privacy layer kind".into()),
    }
}

fn encode_terminal(destination: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = vec![VERSION, TERMINAL];
    encode_field(&mut out, destination)?;
    Ok(out)
}

fn encode_forward(descriptor: &[u8], inner: &[u8]) -> Result<Vec<u8>, String> {
    if inner.len() > MAX_FIELD {
        return Err("nested privacy layer exceeds bound".into());
    }
    let mut out = vec![VERSION, FORWARD];
    encode_field(&mut out, descriptor)?;
    encode_field(&mut out, inner)?;
    Ok(out)
}

fn encode_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), String> {
    if field.len() > MAX_FIELD {
        return Err("privacy layer field exceeds bound".into());
    }
    let len = u16::try_from(field.len()).map_err(|_| "privacy layer field too large")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

fn decode_field(input: &mut &[u8]) -> Result<Vec<u8>, String> {
    let length = input
        .get(..2)
        .ok_or_else(|| "privacy layer field length truncated".to_string())?;
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    *input = &input[2..];
    let field = input
        .get(..length)
        .ok_or_else(|| "privacy layer field truncated".to_string())?;
    let field = field.to_vec();
    *input = &input[length..];
    Ok(field)
}

fn seal_layer(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    PacketKeys::from_traffic_secret(key)
        .map_err(|_| "privacy layer key derivation failed".to_string())?
        .seal(0, AAD, plaintext)
        .map_err(|_| "privacy layer sealing failed".to_string())
}

fn open_layer(key: &[u8; 32], layer: &[u8]) -> Result<Vec<u8>, String> {
    PacketKeys::from_traffic_secret(key)
        .map_err(|_| "privacy layer key derivation failed".to_string())?
        .open(0, AAD, layer)
        .map_err(|_| "privacy layer authentication failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_hop_route_reveals_one_layer_at_a_time() {
        let keys = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let descriptors = vec![b"hop-2-route".to_vec(), b"hop-3-route".to_vec()];
        let destination = b"service-context";
        let mut layer = build_privacy_route(&keys, &descriptors, destination).expect("route");

        let (next, descriptor) = unwrap_privacy_layer(&keys[0], &layer).expect("hop 1");
        assert_eq!(descriptor, Some(descriptors[0].clone()));
        assert!(!next.windows(destination.len()).any(|w| w == destination));
        layer = next;
        let (next, descriptor) = unwrap_privacy_layer(&keys[1], &layer).expect("hop 2");
        assert_eq!(descriptor, Some(descriptors[1].clone()));
        layer = next;
        let (context, descriptor) = unwrap_privacy_layer(&keys[2], &layer).expect("hop 3");
        assert_eq!(context, destination);
        assert_eq!(descriptor, None);
    }

    #[test]
    fn wrong_key_and_bad_shape_fail_closed() {
        let keys = [[1u8; 32], [2u8; 32]];
        let route = build_privacy_route(&keys, &[b"next".to_vec()], b"dest").expect("route");
        assert!(unwrap_privacy_layer(&[9u8; 32], &route).is_err());
        assert!(unwrap_privacy_layer(&keys[0], &route[..route.len() - 1]).is_err());
        assert!(build_privacy_route(&keys, &[], b"dest").is_err());
    }

    #[test]
    fn route_requires_transition_descriptors() {
        let keys = [[1u8; 32], [2u8; 32], [3u8; 32]];
        assert!(build_privacy_route(&keys, &[b"only-one".to_vec()], b"dest").is_err());
    }
}
