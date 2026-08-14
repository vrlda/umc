//! Bounded file-backed shared-memory transfer for large plugin payloads.
//! The private socket directory, launch token, and per-reference token bind
//! each region to one authenticated plugin generation.
#![allow(clippy::missing_errors_doc)]

use rand_core::RngCore;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const MAX_REGION_SIZE: usize = 16 * 1024 * 1024;
pub const DEFAULT_REGION_SIZE: usize = 4 * 1024 * 1024;
pub const DEFAULT_THRESHOLD: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedMemoryDescriptor {
    pub path: PathBuf,
    pub size: usize,
    pub token: Vec<u8>,
}

#[derive(Debug)]
pub enum SharedMemoryError {
    Io(String),
    InvalidSize,
    InvalidReference,
    TokenMismatch,
}

#[derive(Debug)]
pub struct SharedRegion {
    descriptor: SharedMemoryDescriptor,
    file: File,
}

impl SharedRegion {
    pub fn create(path: impl AsRef<Path>, size: usize) -> Result<Self, SharedMemoryError> {
        let size = size.clamp(1, MAX_REGION_SIZE);
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| SharedMemoryError::Io(error.to_string()))?;
        file.set_len(u64::try_from(size).map_err(|_| SharedMemoryError::InvalidSize)?)
            .map_err(|error| SharedMemoryError::Io(error.to_string()))?;
        let mut token = vec![0u8; 32];
        rand_core::OsRng.fill_bytes(&mut token);
        Ok(Self {
            descriptor: SharedMemoryDescriptor { path, size, token },
            file,
        })
    }

    pub fn open(descriptor: SharedMemoryDescriptor) -> Result<Self, SharedMemoryError> {
        if descriptor.size == 0 || descriptor.size > MAX_REGION_SIZE || descriptor.token.len() != 32
        {
            return Err(SharedMemoryError::InvalidSize);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&descriptor.path)
            .map_err(|error| SharedMemoryError::Io(error.to_string()))?;
        Ok(Self { descriptor, file })
    }

    #[must_use]
    pub fn descriptor(&self) -> SharedMemoryDescriptor {
        self.descriptor.clone()
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<(u64, u64, Vec<u8>), SharedMemoryError> {
        if bytes.len() > self.descriptor.size {
            return Err(SharedMemoryError::InvalidReference);
        }
        let mut file = self
            .file
            .try_clone()
            .map_err(|error| SharedMemoryError::Io(error.to_string()))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| SharedMemoryError::Io(error.to_string()))?;
        file.write_all(bytes)
            .map_err(|error| SharedMemoryError::Io(error.to_string()))?;
        file.sync_data()
            .map_err(|error| SharedMemoryError::Io(error.to_string()))?;
        Ok((0, bytes.len() as u64, self.descriptor.token.clone()))
    }

    pub fn read(
        &self,
        offset: u64,
        length: u64,
        token: &[u8],
    ) -> Result<Vec<u8>, SharedMemoryError> {
        if token != self.descriptor.token {
            return Err(SharedMemoryError::TokenMismatch);
        }
        let end = offset
            .checked_add(length)
            .ok_or(SharedMemoryError::InvalidReference)?;
        if end > self.descriptor.size as u64 {
            return Err(SharedMemoryError::InvalidReference);
        }
        let mut file = self
            .file
            .try_clone()
            .map_err(|error| SharedMemoryError::Io(error.to_string()))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| SharedMemoryError::Io(error.to_string()))?;
        let length = usize::try_from(length).map_err(|_| SharedMemoryError::InvalidReference)?;
        let mut bytes = vec![0u8; length];
        file.read_exact(&mut bytes)
            .map_err(|error| SharedMemoryError::Io(error.to_string()))?;
        Ok(bytes)
    }

    pub fn write_reference(
        &mut self,
        bytes: &[u8],
    ) -> Result<crate::proto::umc::plugin::v1::PayloadRef, SharedMemoryError> {
        let (offset, length, token) = self.write(bytes)?;
        Ok(crate::proto::umc::plugin::v1::PayloadRef {
            offset,
            length,
            token,
        })
    }

    pub fn read_reference(
        &self,
        reference: &crate::proto::umc::plugin::v1::PayloadRef,
    ) -> Result<Vec<u8>, SharedMemoryError> {
        self.read(reference.offset, reference.length, &reference.token)
    }
}

impl Drop for SharedRegion {
    fn drop(&mut self) {
        let _ = self.file.sync_data();
        let _ = std::fs::remove_file(&self.descriptor.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_region_round_trips_and_rejects_wrong_token() {
        let path = std::env::temp_dir().join(format!("umc-shared-test-{}", std::process::id()));
        let mut owner = SharedRegion::create(&path, 64).expect("create");
        let descriptor = owner.descriptor();
        let reference = owner.write_reference(b"large payload").expect("write");
        let peer = SharedRegion::open(descriptor).expect("open");
        assert_eq!(
            peer.read_reference(&reference).expect("read"),
            b"large payload"
        );
        let mut bad = reference.clone();
        bad.token[0] ^= 1;
        assert!(matches!(
            peer.read_reference(&bad),
            Err(SharedMemoryError::TokenMismatch)
        ));
    }
}
