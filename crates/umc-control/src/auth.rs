//! Local client authentication (control-api.md §11-12).
use crate::proto::umc::api::v1 as api;
use std::collections::HashMap;
use umc_types::runtime::EntropySource;

pub type PrincipalId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Denied,
    DevelopmentDisabled,
    UnknownToken,
    Expired,
}

/// Token registry: stores keyed hashes of bearer tokens, not plaintext.
#[derive(Debug, Clone)]
pub struct TokenRegistry {
    next_id: PrincipalId,
    tokens: HashMap<Vec<u8>, TokenRecord>,
}

#[derive(Debug, Clone)]
struct TokenRecord {
    principal_id: PrincipalId,
    expires_at_ms: Option<u64>,
}

impl TokenRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: 1,
            tokens: HashMap::new(),
        }
    }

    /// Register a token; returns the principal id and the raw token (returned
    /// to the caller exactly once, control-api.md §43). All 32 bytes of the
    /// token are filled from the entropy source (control-api.md §11.2:
    /// at least 256 bits).
    #[must_use]
    pub fn create_token(
        &mut self,
        expires_at_ms: Option<u64>,
        entropy: &dyn EntropySource,
    ) -> (PrincipalId, Vec<u8>) {
        let principal_id = self.next_id;
        self.next_id += 1;
        let mut raw = vec![0u8; 32];
        entropy.fill(&mut raw);
        let hash = token_hash(&raw);
        self.tokens.insert(
            hash,
            TokenRecord {
                principal_id,
                expires_at_ms,
            },
        );
        (principal_id, raw)
    }

    /// Look up a token and enforce expiry.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::UnknownToken`] for an unregistered token and
    /// [`AuthError::Expired`] once `now_ms` reaches the expiry.
    pub fn authenticate(&self, token: &[u8], now_ms: u64) -> Result<PrincipalId, AuthError> {
        let hash = token_hash(token);
        let record = self.tokens.get(&hash).ok_or(AuthError::UnknownToken)?;
        if let Some(exp) = record.expires_at_ms {
            if now_ms >= exp {
                return Err(AuthError::Expired);
            }
        }
        Ok(record.principal_id)
    }

    pub fn revoke(&mut self, principal_id: PrincipalId) -> bool {
        let before = self.tokens.len();
        self.tokens.retain(|_, r| r.principal_id != principal_id);
        self.tokens.len() != before
    }
}

impl Default for TokenRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn token_hash(token: &[u8]) -> Vec<u8> {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMC-API-TOKEN-v1");
    hasher.update(token);
    hasher.finalize().to_vec()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub principal_id: PrincipalId,
    pub os_peer_authenticated: bool,
    pub bearer_authenticated: bool,
}

/// Evaluate `ClientAuthentication` against local policy.
///
/// # Errors
///
/// Returns [`AuthError::Denied`] when authentication is absent, unknown, or
/// not usable on this connection; [`AuthError::DevelopmentDisabled`] when a
/// development token is presented outside development mode.
pub fn authenticate(
    auth: Option<&api::ClientAuthentication>,
    registry: &TokenRegistry,
    now_ms: u64,
    development_mode: bool,
) -> Result<AuthenticatedPrincipal, AuthError> {
    let Some(auth) = auth else {
        return Err(AuthError::Denied);
    };
    // OS_PEER is proven by the transport (Task 11); here it is a flag.
    let os_peer = auth.method.is_some();
    match &auth.method {
        Some(api::client_authentication::Method::Bearer(b)) => {
            let principal_id = registry.authenticate(&b.token, now_ms)?;
            Ok(AuthenticatedPrincipal {
                principal_id,
                os_peer_authenticated: false,
                bearer_authenticated: true,
            })
        }
        Some(api::client_authentication::Method::Development(_)) => {
            if !development_mode {
                return Err(AuthError::DevelopmentDisabled);
            }
            Ok(AuthenticatedPrincipal {
                principal_id: 0,
                os_peer_authenticated: false,
                bearer_authenticated: false,
            })
        }
        _ if os_peer => Ok(AuthenticatedPrincipal {
            principal_id: 0,
            os_peer_authenticated: true,
            bearer_authenticated: false,
        }),
        _ => Err(AuthError::Denied),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0x42);
        }
    }

    fn bearer_auth(token: Vec<u8>) -> api::ClientAuthentication {
        api::ClientAuthentication {
            method: Some(api::client_authentication::Method::Bearer(
                api::BearerAuthentication { token },
            )),
        }
    }

    #[test]
    fn token_round_trip_and_revocation() {
        let mut registry = TokenRegistry::new();
        let (principal, token) = registry.create_token(None, &E);
        assert_eq!(token.len(), 32);
        assert_eq!(registry.authenticate(&token, 0).unwrap(), principal);
        assert_eq!(
            authenticate(Some(&bearer_auth(token.clone())), &registry, 0, false)
                .unwrap()
                .principal_id,
            principal
        );
        registry.revoke(principal);
        assert_eq!(
            registry.authenticate(&token, 0),
            Err(AuthError::UnknownToken)
        );
    }

    #[test]
    fn token_expiry_enforced() {
        let mut registry = TokenRegistry::new();
        let (_, token) = registry.create_token(Some(100), &E);
        assert_eq!(registry.authenticate(&token, 99).unwrap(), 1);
        assert_eq!(registry.authenticate(&token, 100), Err(AuthError::Expired));
    }

    #[test]
    fn development_tokens_require_development_mode() {
        let registry = TokenRegistry::new();
        let auth = api::ClientAuthentication {
            method: Some(api::client_authentication::Method::Development(
                api::DevelopmentAuthentication { token: Vec::new() },
            )),
        };
        assert_eq!(
            authenticate(Some(&auth), &registry, 0, false),
            Err(AuthError::DevelopmentDisabled)
        );
        assert!(authenticate(Some(&auth), &registry, 0, true).is_ok());
    }

    #[test]
    fn missing_auth_denied() {
        let registry = TokenRegistry::new();
        assert_eq!(
            authenticate(None, &registry, 0, false),
            Err(AuthError::Denied)
        );
    }
}
