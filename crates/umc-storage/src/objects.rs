//! Content-addressed object store (storage.md §11): two-level hash directories.
use crate::store::StoreError;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectStore {
    root: PathBuf,
}

impl ObjectStore {
    /// Opens (creating if needed) the object store root at `root`.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the `objects` directory cannot be created.
    pub fn open(root: PathBuf) -> Result<Self, StoreError> {
        std::fs::create_dir_all(root.join("objects"))
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        Ok(Self { root })
    }

    fn object_path(&self, id: &[u8; 32]) -> PathBuf {
        use std::fmt::Write as _;
        let mut hex = String::with_capacity(64);
        for b in id {
            write!(hex, "{b:02x}").expect("writing to String cannot fail");
        }
        self.root.join("objects").join(&hex[..2]).join(&hex)
    }

    /// Atomic write: temp file + rename (storage.md §11.2).
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the content hash is wrong or the
    /// write, sync, or rename fails.
    pub fn put(&self, id: &[u8; 32], bytes: &[u8]) -> Result<(), StoreError> {
        if blake2s(bytes) != *id {
            return Err(StoreError::Corrupt("object hash mismatch".into()));
        }
        let path = self.object_path(id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        }
        let tmp = path.with_extension("tmp");
        let mut file =
            std::fs::File::create(&tmp).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        file.write_all(bytes)
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        file.sync_all()
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        drop(file);
        std::fs::rename(&tmp, &path).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        }
        Ok(())
    }

    /// Read with hash validation (storage.md §11.2): mismatched content is corrupt.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] if the object is absent, or
    /// [`StoreError::Corrupt`] if its content does not match `id`.
    pub fn get(&self, id: &[u8; 32]) -> Result<Vec<u8>, StoreError> {
        let bytes = std::fs::read(self.object_path(id)).map_err(|_| StoreError::NotFound)?;
        let actual = blake2s(&bytes);
        if actual != *id {
            return Err(StoreError::Corrupt("object hash mismatch".into()));
        }
        Ok(bytes)
    }

    /// Removes the object; missing objects are a no-op.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the file cannot be removed.
    pub fn delete(&self, id: &[u8; 32]) -> Result<(), StoreError> {
        let path = self.object_path(id);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        }
        Ok(())
    }

    #[must_use]
    pub fn exists(&self, id: &[u8; 32]) -> bool {
        self.object_path(id).exists()
    }
}

#[must_use]
pub fn blake2s(bytes: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("umc-objects-{}-{n}", std::process::id()))
    }

    #[test]
    fn put_get_round_trip() {
        let root = temp_root();
        let _ = std::fs::remove_dir_all(&root);
        let store = ObjectStore::open(root.clone()).unwrap();
        let bytes = b"bundle payload".to_vec();
        let id = blake2s(&bytes);
        store.put(&id, &bytes).unwrap();
        assert_eq!(store.get(&id).unwrap(), bytes);
        let path = store.object_path(&id);
        assert!(path.starts_with(root.join("objects")));
    }

    #[test]
    fn hash_mismatch_detected() {
        let root = temp_root();
        let _ = std::fs::remove_dir_all(&root);
        let store = ObjectStore::open(root).unwrap();
        let bytes = b"payload".to_vec();
        let id = blake2s(&bytes);
        store.put(&id, &bytes).unwrap();
        // Corrupt the file.
        let path = store.object_path(&id);
        std::fs::write(&path, b"tampered").unwrap();
        assert!(matches!(store.get(&id), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn missing_object_is_not_found() {
        let root = temp_root();
        let _ = std::fs::remove_dir_all(&root);
        let store = ObjectStore::open(root).unwrap();
        assert_eq!(store.get(&[0u8; 32]), Err(StoreError::NotFound));
    }

    #[test]
    fn wrong_content_hash_is_rejected_before_write() {
        let root = temp_root();
        let _ = std::fs::remove_dir_all(&root);
        let store = ObjectStore::open(root).unwrap();
        let id = [0u8; 32];
        assert!(matches!(
            store.put(&id, b"payload"),
            Err(StoreError::Corrupt(message)) if message == "object hash mismatch"
        ));
        assert!(!store.exists(&id));
    }
}
