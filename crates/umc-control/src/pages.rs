//! Opaque page tokens (control-api.md §37): authenticated, principal-bound,
//! method-bound, expiring.
use umc_types::runtime::EntropySource;

pub const DEFAULT_PAGE_SIZE: u32 = 100;
pub const MAX_PAGE_SIZE: u32 = 1_000;
pub const PAGE_TOKEN_TTL_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageToken {
    pub offset: u64,
    pub principal_id: u64,
    pub method: String,
    pub issued_at_ms: u64,
    pub salt: [u8; 8],
}

impl PageToken {
    #[must_use]
    pub fn issue(
        offset: u64,
        principal_id: u64,
        method: &str,
        issued_at_ms: u64,
        entropy: &dyn EntropySource,
    ) -> Self {
        let mut salt = [0u8; 8];
        entropy.fill(&mut salt);
        Self {
            offset,
            principal_id,
            method: method.to_string(),
            issued_at_ms,
            salt,
        }
    }

    #[must_use]
    pub fn validate(&self, principal_id: u64, method: &str, now_ms: u64) -> bool {
        self.principal_id == principal_id
            && self.method == method
            && now_ms < self.issued_at_ms + PAGE_TOKEN_TTL_MS
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&self.principal_id.to_be_bytes());
        out.extend_from_slice(self.method.as_bytes());
        out.push(0);
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out
    }

    /// Parse a token previously produced by [`PageToken::encode`].
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 + 8 + 1 + 8 + 8 {
            return None;
        }
        let offset = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
        let principal_id = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
        let method_end = bytes[16..].iter().position(|&b| b == 0)? + 16;
        let method = std::str::from_utf8(bytes.get(16..method_end)?)
            .ok()?
            .to_string();
        let rest = &bytes[method_end + 1..];
        let issued_at_ms = u64::from_be_bytes(rest.get(0..8)?.try_into().ok()?);
        let mut salt = [0u8; 8];
        salt.copy_from_slice(rest.get(8..16)?);
        Some(Self {
            offset,
            principal_id,
            method,
            issued_at_ms,
            salt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(3);
        }
    }

    #[test]
    fn page_token_round_trip_and_validation() {
        let t = PageToken::issue(250, 9, "ListPeers", 1_000, &E);
        let enc = t.encode();
        let dec = PageToken::decode(&enc).unwrap();
        assert_eq!(dec.offset, 250);
        assert_eq!(dec.principal_id, 9);
        assert_eq!(dec.method, "ListPeers");
        assert!(dec.validate(9, "ListPeers", 1_500));
        assert!(!dec.validate(10, "ListPeers", 1_500));
        assert!(!dec.validate(9, "Other", 1_500));
        assert!(!dec.validate(9, "ListPeers", 1_000 + PAGE_TOKEN_TTL_MS));
    }

    #[test]
    fn truncated_tokens_are_rejected() {
        let t = PageToken::issue(1, 2, "ListPeers", 100, &E);
        let enc = t.encode();
        assert!(PageToken::decode(&enc[..enc.len() - 1]).is_none());
        assert!(PageToken::decode(&enc[..10]).is_none());
        assert!(PageToken::decode(b"").is_none());
    }
}
