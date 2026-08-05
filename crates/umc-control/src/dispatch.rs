//! Request dispatch (control-api.md §16-21): correlation, idempotency, limits.
use crate::proto::umc::api::v1 as api;
use std::collections::HashMap;

pub const MAX_CONCURRENT_REQUESTS: usize = 64;
pub const MAX_QUEUED_REQUESTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    DuplicateRequestId,
    TooManyConcurrent,
    IdempotencyConflict,
    UnknownMethod,
}

#[derive(Debug, Clone)]
pub struct Inflight {
    pub request_id: u64,
    pub service: String,
    pub method: String,
    pub idempotency_key: Vec<u8>,
}

#[derive(Debug)]
pub struct Dispatcher {
    inflight: HashMap<u64, Inflight>,
    idempotent_results: HashMap<Vec<u8>, Vec<u8>>,
}

impl Dispatcher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inflight: HashMap::new(),
            idempotent_results: HashMap::new(),
        }
    }

    /// Register an in-flight request.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::TooManyConcurrent`] at the concurrency limit,
    /// [`DispatchError::DuplicateRequestId`] for a reused request id, and
    /// [`DispatchError::IdempotencyConflict`] for a replayed idempotency key.
    pub fn submit(&mut self, request: &api::Request) -> Result<(), DispatchError> {
        if self.inflight.len() >= MAX_CONCURRENT_REQUESTS {
            return Err(DispatchError::TooManyConcurrent);
        }
        if self.inflight.contains_key(&request.request_id) {
            return Err(DispatchError::DuplicateRequestId);
        }
        if !request.idempotency_key.is_empty()
            && self
                .idempotent_results
                .contains_key(&request.idempotency_key)
        {
            return Err(DispatchError::IdempotencyConflict);
        }
        self.inflight.insert(
            request.request_id,
            Inflight {
                request_id: request.request_id,
                service: request.service.clone(),
                method: request.method.clone(),
                idempotency_key: request.idempotency_key.clone(),
            },
        );
        Ok(())
    }

    pub fn complete(&mut self, request_id: u64, result: &[u8]) {
        if let Some(inflight) = self.inflight.remove(&request_id) {
            if !inflight.idempotency_key.is_empty() {
                self.idempotent_results
                    .insert(inflight.idempotency_key, result.to_vec());
                if self.idempotent_results.len() > 10_000 {
                    self.idempotent_results.clear();
                }
            }
        }
    }

    #[must_use]
    pub fn cancel(&mut self, request_id: u64) -> bool {
        self.inflight.remove(&request_id).is_some()
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: u64, service: &str, method: &str) -> api::Request {
        api::Request {
            request_id: id,
            service: service.to_string(),
            method: method.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn duplicate_inflight_rejected() {
        let mut d = Dispatcher::new();
        d.submit(&request(1, "NodeAdmin", "GetStatus")).unwrap();
        assert_eq!(
            d.submit(&request(1, "NodeAdmin", "GetStatus")),
            Err(DispatchError::DuplicateRequestId)
        );
    }

    #[test]
    fn concurrent_limit_enforced() {
        let mut d = Dispatcher::new();
        for i in 0..MAX_CONCURRENT_REQUESTS {
            d.submit(&request(i as u64, "s", "m")).unwrap();
        }
        assert_eq!(
            d.submit(&request(MAX_CONCURRENT_REQUESTS as u64, "s", "m")),
            Err(DispatchError::TooManyConcurrent)
        );
    }

    #[test]
    fn idempotency_key_conflict() {
        let mut d = Dispatcher::new();
        let mut r = request(1, "s", "m");
        r.idempotency_key = b"key".to_vec();
        d.submit(&r).unwrap();
        d.complete(1, b"result");
        let mut r2 = request(2, "s", "m");
        r2.idempotency_key = b"key".to_vec();
        assert_eq!(d.submit(&r2), Err(DispatchError::IdempotencyConflict));
    }

    #[test]
    fn cancel_removes_inflight() {
        let mut d = Dispatcher::new();
        d.submit(&request(1, "s", "m")).unwrap();
        assert!(d.cancel(1));
        assert!(!d.cancel(1));
        d.submit(&request(1, "s", "m")).unwrap();
    }
}
