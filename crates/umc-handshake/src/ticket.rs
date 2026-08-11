//! Session-ticket encryption (handshake.md §35): server-encrypted blobs with
//! a rotating ticket key.
use umc_crypto::aead::PacketKeys;

pub const MAX_TICKET_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const TICKET_ENTROPY: usize = 16;

/// Label for per-ticket seal-key derivation (handshake.md §35): the AEAD
/// key is bound to the ticket's clear nonce, so two tickets never seal
/// under the same (key, nonce) pairing even though the server's ticket
/// key is stable for its lifetime.
const TICKET_SEAL_LABEL: &[u8] = b"ticket seal";

/// Derives the per-ticket AEAD seal key: `expand_label(ticket_key,
/// "ticket seal", nonce, 32)`. The nonce rides in the clear prefix of the
/// v1 wire format, so both `issue_ticket` and `validate_ticket` can
/// derive it; a swapped or forged prefix derives a different key and the
/// seal fails.
#[must_use]
fn ticket_seal_key(ticket_key: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    umc_crypto::label::expand_label(ticket_key, TICKET_SEAL_LABEL, nonce, 32)
        .expect("32-byte expansion")
        .try_into()
        .expect("32-byte expansion")
}

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

/// Encrypts a ticket payload under the server's current ticket key,
/// wrapping it in the v1 ticket wire format:
///
/// ```text
/// [version(1) || nonce(16) || sealed(payload.encode())]
/// ```
///
/// The nonce rides in the clear BEFORE the seal (SANCTIONED v1 format,
/// handshake.md §35): the bearer must be able to derive the resumption PSK
/// (`resumption_psk(resumption_secret, nonce)`) without opening the seal.
/// The seal authenticates the whole ticket: the AEAD key is derived from
/// the ticket key AND the nonce (`ticket_seal_key`), so each ticket seals
/// under its own unique key even at packet number 0 — a swapped nonce
/// derives a different key and fails `validate_ticket`, and no two tickets
/// share an AEAD (key, nonce) pairing.
///
/// # Panics
/// Panics if the 32-byte ticket key cannot be expanded into keys or the
/// authenticated encryption fails; both are impossible for valid input.
#[must_use]
pub fn issue_ticket(ticket_key: &[u8; 32], payload: &TicketPayload) -> Vec<u8> {
    let seal_key = ticket_seal_key(ticket_key, &payload.nonce);
    let keys = PacketKeys::from_traffic_secret(&seal_key).expect("32-byte key");
    let seal = keys
        .seal(0, b"UMP-SESSION-TICKET-v1", &payload.encode())
        .expect("seal");
    let mut out = Vec::with_capacity(1 + TICKET_ENTROPY + seal.len());
    out.push(TICKET_VERSION);
    out.extend_from_slice(&payload.nonce);
    out.extend_from_slice(&seal);
    out
}

/// The v1 ticket wire-format version byte.
pub const TICKET_VERSION: u8 = 1;

/// Reads the ticket's clear nonce prefix (v1 wire format: `[version(1) ||
/// nonce(16) || sealed(...)]`). The bearer cannot open the seal (the ticket
/// is sealed with the server's key) but needs the nonce to derive the
/// resumption PSK; the seal authenticates the whole ticket, so a forged
/// prefix is rejected server-side.
#[must_use]
pub fn ticket_nonce(ticket: &[u8]) -> Option<[u8; TICKET_ENTROPY]> {
    if ticket.first().copied()? != TICKET_VERSION {
        return None;
    }
    ticket.get(1..1 + TICKET_ENTROPY)?.try_into().ok()
}

/// Decrypts and validates a ticket issued by this server (v1 wire format:
/// `[version(1) || nonce(16) || sealed(payload.encode())]` — the clear
/// nonce prefix must match the nonce sealed inside).
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
    let nonce = ticket_nonce(ticket).ok_or(TicketError::Invalid)?;
    let seal = ticket
        .get(1 + TICKET_ENTROPY..)
        .ok_or(TicketError::Invalid)?;
    // The seal key derives from the clear nonce prefix, mirroring
    // `issue_ticket`: a tampered prefix derives the wrong key and the
    // seal fails before any payload comparison.
    let seal_key = ticket_seal_key(ticket_key, &nonce);
    let keys = PacketKeys::from_traffic_secret(&seal_key).map_err(|_| TicketError::Invalid)?;
    let plaintext = keys
        .open(0, b"UMP-SESSION-TICKET-v1", seal)
        .map_err(|_| TicketError::Invalid)?;
    let payload = TicketPayload::decode(&plaintext).ok_or(TicketError::Invalid)?;
    if payload.version != TICKET_VERSION {
        return Err(TicketError::Invalid);
    }
    if payload.nonce != nonce {
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

    /// The v1 wire format (handshake.md §35): the nonce rides in the clear
    /// prefix `[version(1) || nonce(16) || seal]` so the bearer can derive
    /// the resumption PSK without opening the seal; `validate_ticket`
    /// returns the same payload and the seal authenticates the whole
    /// ticket — a tampered prefix fails, as does the wrong key.
    #[test]
    fn ticket_nonce_round_trip() {
        let key = [3u8; 32];
        let now = 1_700_000_000_000;
        let ticket = issue_ticket(&key, &payload(now));
        assert_eq!(ticket.first(), Some(&TICKET_VERSION));
        assert_eq!(
            ticket_nonce(&ticket),
            Some([5u8; TICKET_ENTROPY]),
            "the nonce must be readable in the clear prefix"
        );
        let back = validate_ticket(&key, &ticket, now + 60_000).expect("valid ticket");
        assert_eq!(back.nonce, [5u8; TICKET_ENTROPY]);
        assert_eq!(back.resumption_secret, [4u8; 32]);

        // A tampered clear nonce fails validation (the sealed copy must
        // match the prefix) — the bearer cannot forge a PSK nonce.
        let mut forged = ticket.clone();
        forged[1] ^= 0x01;
        assert_eq!(
            validate_ticket(&key, &forged, now + 60_000),
            Err(TicketError::Invalid)
        );
        // A truncated ticket has no readable nonce.
        assert!(ticket_nonce(&ticket[..10]).is_none());
        assert!(ticket_nonce(b"\x02garbage").is_none());
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

    /// The v1 seal key is bound to the ticket's clear nonce (handshake.md
    /// §35): every ticket seals under its own derived AEAD key, so the
    /// constant (ticket key, PN 0) pairing cannot be reused across tickets
    /// (a known-plaintext pairing attack would otherwise recover victim
    /// ticket plaintexts).
    #[test]
    fn tickets_do_not_share_aead_keys() {
        let key = [9u8; 32];
        let now = 1_700_000_000_000;
        let mut a = payload(now);
        let mut b = payload(now);
        a.nonce = [0xA1u8; TICKET_ENTROPY];
        b.nonce = [0xB2u8; TICKET_ENTROPY];
        let ticket_a = issue_ticket(&key, &a);
        let ticket_b = issue_ticket(&key, &b);

        // The fix contract: a ticket opens under the seal key derived
        // from its OWN clear nonce (and only under that one).
        let keys_a =
            PacketKeys::from_traffic_secret(&ticket_seal_key(&key, &a.nonce)).expect("seal key");
        let keys_b =
            PacketKeys::from_traffic_secret(&ticket_seal_key(&key, &b.nonce)).expect("seal key");
        assert!(
            keys_a
                .open(0, b"UMP-SESSION-TICKET-v1", &ticket_a[1 + TICKET_ENTROPY..])
                .is_ok(),
            "a ticket must open under the seal key bound to its own nonce"
        );
        assert!(
            keys_b
                .open(0, b"UMP-SESSION-TICKET-v1", &ticket_a[1 + TICKET_ENTROPY..])
                .is_err(),
            "a ticket must not open under another ticket's seal key"
        );
        assert!(
            keys_a
                .open(0, b"UMP-SESSION-TICKET-v1", &ticket_b[1 + TICKET_ENTROPY..])
                .is_err(),
            "a ticket must not open under another ticket's seal key"
        );

        // Swapping a ticket's clear nonce for another ticket's nonce
        // fails: the validator derives the seal key from the (tampered)
        // prefix, so the seal breaks before any payload comparison.
        let mut swapped = ticket_a.clone();
        swapped[1..=TICKET_ENTROPY].copy_from_slice(&b.nonce);
        assert_eq!(
            validate_ticket(&key, &swapped, now + 60_000),
            Err(TicketError::Invalid),
            "the seal must bind the nonce via the key derivation"
        );
        let mut swapped_back = ticket_b.clone();
        swapped_back[1..=TICKET_ENTROPY].copy_from_slice(&a.nonce);
        assert_eq!(
            validate_ticket(&key, &swapped_back, now + 60_000),
            Err(TicketError::Invalid),
            "the seal must bind the nonce via the key derivation"
        );
    }
}
