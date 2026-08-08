//! Bounded large-bundle transfer (bundles.md §8.2, §24).
//!
//! The live `BUNDLE` frame remains packet-sized. Applications that need to
//! move a larger envelope use these 256 KiB stream chunks; a receiver accepts
//! at most 4 MiB for one in-flight reassembly and can complete chunks in any
//! order without allocating the declared final size up front.

use std::collections::BTreeMap;

pub const STREAM_CHUNK_SIZE: usize = 256 * 1024;
pub const MAX_REASSEMBLY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleChunk {
    pub bundle_id: [u8; 32],
    pub chunk_index: u64,
    pub chunk_final: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    WrongBundle,
    ChunkTooLarge,
    ReassemblyTooLarge,
    ConflictingChunk,
    IndexOverflow,
}

/// Splits an encrypted bundle envelope into bounded stream chunks.
#[must_use]
pub fn split_bundle(bundle_id: [u8; 32], payload: &[u8]) -> Vec<BundleChunk> {
    if payload.is_empty() {
        return vec![BundleChunk {
            bundle_id,
            chunk_index: 0,
            chunk_final: true,
            payload: Vec::new(),
        }];
    }
    let count = payload.len().div_ceil(STREAM_CHUNK_SIZE);
    payload
        .chunks(STREAM_CHUNK_SIZE)
        .enumerate()
        .map(|(index, chunk)| BundleChunk {
            bundle_id,
            chunk_index: index as u64,
            chunk_final: index + 1 == count,
            payload: chunk.to_vec(),
        })
        .collect()
}

#[derive(Debug)]
pub struct BundleReassembler {
    bundle_id: [u8; 32],
    chunks: BTreeMap<u64, Vec<u8>>,
    final_index: Option<u64>,
    total_bytes: usize,
}

impl BundleReassembler {
    #[must_use]
    pub fn new(bundle_id: [u8; 32]) -> Self {
        Self {
            bundle_id,
            chunks: BTreeMap::new(),
            final_index: None,
            total_bytes: 0,
        }
    }

    /// Adds one chunk and returns the complete envelope once all chunks are
    /// present. Exact duplicate chunks are idempotent; conflicting bytes are
    /// rejected without replacing the accepted copy.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong bundle id, oversized chunks/reassemblies,
    /// conflicting duplicate bytes, or an index that cannot be represented
    /// in the bounded reassembly map.
    pub fn push(&mut self, chunk: BundleChunk) -> Result<Option<Vec<u8>>, TransferError> {
        if chunk.bundle_id != self.bundle_id {
            return Err(TransferError::WrongBundle);
        }
        if chunk.payload.len() > STREAM_CHUNK_SIZE {
            return Err(TransferError::ChunkTooLarge);
        }
        if chunk.chunk_index > (MAX_REASSEMBLY_BYTES / STREAM_CHUNK_SIZE) as u64 {
            return Err(TransferError::IndexOverflow);
        }
        if let Some(existing) = self.chunks.get(&chunk.chunk_index) {
            if existing != &chunk.payload {
                return Err(TransferError::ConflictingChunk);
            }
        } else {
            let next_total = self
                .total_bytes
                .checked_add(chunk.payload.len())
                .ok_or(TransferError::ReassemblyTooLarge)?;
            if next_total > MAX_REASSEMBLY_BYTES {
                return Err(TransferError::ReassemblyTooLarge);
            }
            self.total_bytes = next_total;
            self.chunks.insert(chunk.chunk_index, chunk.payload);
        }
        if chunk.chunk_final {
            if self
                .final_index
                .is_some_and(|prior| prior != chunk.chunk_index)
            {
                return Err(TransferError::ConflictingChunk);
            }
            self.final_index = Some(chunk.chunk_index);
        }
        let Some(final_index) = self.final_index else {
            return Ok(None);
        };
        let final_count = usize::try_from(final_index).map_err(|_| TransferError::IndexOverflow)?;
        if self.chunks.len() != final_count + 1 || !self.chunks.keys().copied().eq(0..=final_index)
        {
            return Ok(None);
        }
        let mut payload = Vec::with_capacity(self.total_bytes);
        for chunk in self.chunks.values() {
            payload.extend_from_slice(chunk);
        }
        Ok(Some(payload))
    }

    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_reassemble_out_of_order() {
        let id = [7u8; 32];
        let payload = vec![0xA5; STREAM_CHUNK_SIZE * 2 + 17];
        let chunks = split_bundle(id, &payload);
        assert_eq!(chunks.len(), 3);
        assert!(!chunks[0].chunk_final);
        assert!(chunks[2].chunk_final);

        let mut receiver = BundleReassembler::new(id);
        assert!(receiver.push(chunks[2].clone()).unwrap().is_none());
        assert!(receiver.push(chunks[0].clone()).unwrap().is_none());
        assert_eq!(receiver.push(chunks[1].clone()).unwrap(), Some(payload));
    }

    #[test]
    fn duplicate_is_idempotent_and_conflict_is_rejected() {
        let id = [3u8; 32];
        let chunk = BundleChunk {
            bundle_id: id,
            chunk_index: 0,
            chunk_final: true,
            payload: b"payload".to_vec(),
        };
        let mut receiver = BundleReassembler::new(id);
        assert_eq!(
            receiver.push(chunk.clone()).unwrap(),
            Some(b"payload".to_vec())
        );
        assert_eq!(
            receiver.push(chunk.clone()).unwrap(),
            Some(b"payload".to_vec())
        );
        let mut conflict = chunk;
        conflict.payload = b"other".to_vec();
        assert_eq!(
            receiver.push(conflict),
            Err(TransferError::ConflictingChunk)
        );
    }

    #[test]
    fn reassembly_is_bounded() {
        let id = [9u8; 32];
        let mut receiver = BundleReassembler::new(id);
        let too_large = BundleChunk {
            bundle_id: id,
            chunk_index: 0,
            chunk_final: false,
            payload: vec![0u8; MAX_REASSEMBLY_BYTES],
        };
        assert_eq!(receiver.push(too_large), Err(TransferError::ChunkTooLarge));
    }
}
