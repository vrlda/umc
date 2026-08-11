//! Bounded application output queue (sdk.md §24, resource-limits.md).
#![allow(clippy::missing_errors_doc)]
use std::collections::VecDeque;

use crate::client::ClientError;

/// A byte-bounded queue used by embedded and daemon stream adapters. It
/// refuses a chunk that would exceed the configured limit instead of growing
/// without bound.
#[derive(Debug)]
pub struct BoundedSendQueue {
    maximum_bytes: usize,
    queued_bytes: usize,
    chunks: VecDeque<Vec<u8>>,
}

impl BoundedSendQueue {
    #[must_use]
    pub fn new(maximum_bytes: usize) -> Self {
        Self {
            maximum_bytes,
            queued_bytes: 0,
            chunks: VecDeque::new(),
        }
    }

    /// Enqueues one owned chunk or reports explicit backpressure.
    pub fn try_enqueue(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
        if bytes.len() > self.maximum_bytes.saturating_sub(self.queued_bytes) {
            return Err(ClientError::WouldBlock);
        }
        self.queued_bytes += bytes.len();
        self.chunks.push_back(bytes.to_vec());
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let chunk = self.chunks.pop_front()?;
        self.queued_bytes = self.queued_bytes.saturating_sub(chunk.len());
        Some(chunk)
    }

    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    #[must_use]
    pub const fn maximum_bytes(&self) -> usize {
        self.maximum_bytes
    }
}
