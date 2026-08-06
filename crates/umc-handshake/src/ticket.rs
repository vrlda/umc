//! Session-ticket encryption (handshake.md §35): server-encrypted blobs with
//! a rotating ticket key.
use umc_crypto::aead::PacketKeys;

pub const MAX_TICKET_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const TICKET_ENTROPY: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketPayload {
    pub version: u8,
    pub ticket_id: [u8; 16],
    pub client_endpoint_id_hash: [u8; 32],
    pub server_endpoint_id_hash: [u8; 32],
    pub resumption_secret: [u8; 32],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub protocol_version: u32,
    pub crypto_profile: Vec<u8>,
    pub nonce: [u8; TICKET_ENTROPY],
}

impl TicketPayload {
    /// Serializes the payload: fixed fields, then the NUL-terminated crypto
    /// profile, then the nonce.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.version);
        out.extend_from_slice(&self.ticket_id);
        out.extend_from_slice(&self.client_endpoint_id_hash);
        out.extend_from_slice(&self.server_endpoint_id_hash);
        out.extend_from_slice(&self.resumption_secret);
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.crypto_profile);
        out.push(0);
        out.extend_from_slice(&self.nonce);
        out
    }

    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Self> {
        let version = *body.first()?;
        let mut pos = 1;
        let take = |n: usize, pos: &mut usize| -> Option<&[u8]> {
            let s = body.get(*pos..*pos + n)?;
            *pos += n;
            Some(s)
        };
        let ticket_id = take(16, &mut pos)?.try_into().ok()?;
        let client_endpoint_id_hash = take(32, &mut pos)?.try_into().ok()?;
        let server_endpoint_id_hash = take(32, &mut pos)?.try_into().ok()?;
        let resumption_secret = take(32, &mut pos)?.try_into().ok()?;
        let issued_at_ms = u64::from_be_bytes(take(8, &mut pos)?.try_into().ok()?);
        let expires_at_ms = u64::from_be_bytes(take(8, &mut pos)?.try_into().ok()?);
        let protocol_version = u32::from_be_bytes(take(4, &mut pos)?.try_into().ok()?);
        let rest = take(body.len().saturating_sub(pos), &mut pos)?;
        let (crypto_profile, nonce) = match rest.iter().position(|&b| b == 0) {
            Some(idx) => (&rest[..idx], rest[idx + 1..].to_vec()),
            None => return None,
        };
        let nonce: [u8; TICKET_ENTROPY] = nonce.try_into().ok()?;
        Some(Self {
            version,
            ticket_id,
            client_endpoint_id_hash,
            server_endpoint_id_hash,
            resumption_secret,
            issued_at_ms,
            expires_at_ms,
            protocol_version,
            crypto_profile: crypto_profile.to_vec(),
            nonce,
        })
    }
}

/// Encrypts a ticket payload under the server's current ticket key.
///
/// # Panics
/// Panics if the 32-byte ticket key cannot be expanded into keys or the
/// authenticated encryption fails; both are impossible for valid input.
#[must_use]
pub fn issue_ticket(ticket_key: &[u8; 32], payload: &TicketPayload) -> Vec<u8> {
    let keys = PacketKeys::from_traffic_secret(ticket_key).expect("32-byte key");
    keys.seal(0, b"UMP-SESSION-TICKET-v1", &payload.encode())
        .expect("seal")
}

/// Decrypts and validates a ticket issued by this server.
///
/// # Errors
/// Returns [`TicketError::Invalid`] for an undecryptable, malformed, or
/// over-long-lived ticket, and [`TicketError::Expired`] when the ticket is
/// past its expiry.
pub fn validate_ticket(
    ticket_key: &[u8; 32],
    ticket: &[u8],
    now_ms: u64,
) -> Result<TicketPayload, TicketError> {
    let keys = PacketKeys::from_traffic_secret(ticket_key).map_err(|_| TicketError::Invalid)?;
    let plaintext = keys
        .open(0, b"UMP-SESSION-TICKET-v1", ticket)
        .map_err(|_| TicketError::Invalid)?;
    let payload = TicketPayload::decode(&plaintext).ok_or(TicketError::Invalid)?;
    if payload.version != 1 {
        return Err(TicketError::Invalid);
    }
    if payload.expires_at_ms <= now_ms {
        return Err(TicketError::Expired);
    }
    if payload.expires_at_ms.saturating_sub(payload.issued_at_ms) > MAX_TICKET_LIFETIME_MS {
        return Err(TicketError::Invalid);
    }
    Ok(payload)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    Invalid,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(now: u64) -> TicketPayload {
        TicketPayload {
            version: 1,
            ticket_id: [1u8; 16],
            client_endpoint_id_hash: [2u8; 32],
            server_endpoint_id_hash: [3u8; 32],
            resumption_secret: [4u8; 32],
            issued_at_ms: now,
            expires_at_ms: now + 3_600_000,
            protocol_version: 1,
            crypto_profile: b"UMP-CRYPTO-1".to_vec(),
            nonce: [5u8; TICKET_ENTROPY],
        }
    }

    #[test]
    fn ticket_round_trip() {
        let key = [1u8; 32];
        let now = 1_700_000_000_000;
        let ticket = issue_ticket(&key, &payload(now));
        let back = validate_ticket(&key, &ticket, now + 60_000).unwrap();
        assert_eq!(back.resumption_secret, [4u8; 32]);
        assert_eq!(back.client_endpoint_id_hash, [2u8; 32]);
    }

    #[test]
    fn expired_ticket_rejected() {
        let key = [1u8; 32];
        let now = 1_700_000_000_000;
        let ticket = issue_ticket(&key, &payload(now));
        assert_eq!(
            validate_ticket(&key, &ticket, now + 3_600_001),
            Err(TicketError::Expired)
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let now = 1_700_000_000_000;
        let ticket = issue_ticket(&[1u8; 32], &payload(now));
        assert_eq!(
            validate_ticket(&[2u8; 32], &ticket, now),
            Err(TicketError::Invalid)
        );
    }

    #[test]
    fn lifetime_capped_at_24h() {
        let key = [1u8; 32];
        let now = 1_700_000_000_000;
        let mut p = payload(now);
        p.expires_at_ms = now + 25 * 60 * 60 * 1000;
        let ticket = issue_ticket(&key, &p);
        assert_eq!(
            validate_ticket(&key, &ticket, now + 1),
            Err(TicketError::Invalid)
        );
    }
}
