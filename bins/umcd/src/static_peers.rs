//! Static peer bootstrap (discovery.md §15).

use crate::config::StaticPeerConfig;
use crate::state::RuntimeState;
use std::sync::{Arc, Mutex};

/// Parses the canonical 32-byte endpoint id representation used by config
/// and logs (64 hexadecimal characters, optional `0x` prefix).
pub fn parse_endpoint_id(value: &str) -> Result<[u8; 32], String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return Err(format!(
            "endpoint id must be 64 hex characters, got {}",
            value.len()
        ));
    }
    let mut endpoint_id = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| format!("invalid endpoint id at {index}"))?;
        let low = hex_nibble(pair[1]).ok_or_else(|| format!("invalid endpoint id at {index}"))?;
        endpoint_id[index] = (high << 4) | low;
    }
    Ok(endpoint_id)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Attempts one bounded dial for every configured static peer. The node
/// mutex is held only for the handshake call; endpoint matching is enforced
/// inside `Node::connect_to_endpoint`.
#[allow(clippy::await_holding_lock)]
pub async fn dial_all(state: &Arc<Mutex<RuntimeState>>, peers: &[StaticPeerConfig]) {
    for peer in peers {
        let endpoint_id = match parse_endpoint_id(&peer.endpoint_id) {
            Ok(endpoint_id) => endpoint_id,
            Err(error) => {
                log::warn!("[discovery] static peer {} rejected: {error}", peer.address);
                continue;
            }
        };
        let (disabled, carrier) = {
            let state = state.lock().expect("runtime state");
            (
                state.config.carrier_disabled(&peer.carrier),
                peer.carrier.clone(),
            )
        };
        if disabled {
            log::debug!("[discovery] static peer carrier {carrier} disabled");
            continue;
        }
        let result = {
            let mut state = state.lock().expect("runtime state");
            state
                .node
                .connect_to_endpoint(&carrier, peer.address.clone(), endpoint_id)
                .await
        };
        match result {
            Ok(session_id) => log::info!(
                "[discovery] static peer {} connected (session {session_id})",
                peer.address
            ),
            Err(error) => log::debug!(
                "[discovery] static peer {} dial failed: {error:?}",
                peer.address
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_id_parser_accepts_hex_forms() {
        let plain = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert_eq!(parse_endpoint_id(plain).unwrap()[0], 0);
        assert_eq!(parse_endpoint_id(&format!("0x{plain}")).unwrap()[31], 0xff);
        assert!(parse_endpoint_id("bad").is_err());
        assert!(parse_endpoint_id(&plain[..63]).is_err());
    }
}
