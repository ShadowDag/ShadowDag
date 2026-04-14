// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::StorageError;

pub trait KeyValueStore: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError>;
    fn delete(&self, key: &[u8]) -> Result<(), StorageError>;
    fn exists(&self, key: &[u8]) -> Result<bool, StorageError> {
        self.get(key).map(|opt| opt.is_some())
    }
}

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct MemoryStore {
    data: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }
}

impl KeyValueStore for MemoryStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let guard = self
            .data
            .read()
            .map_err(|e| StorageError::LockPoisoned(e.to_string()))?;
        Ok(guard.get(key).cloned())
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.data
            .write()
            .map_err(|e| StorageError::LockPoisoned(e.to_string()))?
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        self.data
            .write()
            .map_err(|e| StorageError::LockPoisoned(e.to_string()))?
            .remove(key);
        Ok(())
    }
}

pub enum StorageBackend {
    Memory,
    RocksDB(String),
}

/// RocksDB-backed KeyValueStore implementation.
/// Uses the REAL RocksDB — data persists across restarts.
pub struct RocksStore {
    db: Arc<rocksdb::DB>,
}

impl RocksStore {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, path).map_err(|e| StorageError::OpenFailed {
            path: path.to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self { db: Arc::new(db) })
    }
}

impl KeyValueStore for RocksStore {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        match self.db.get(key) {
            Ok(v) => Ok(v.map(|v| v.to_vec())),
            Err(e) => {
                crate::slog_error!("storage", "read_failed", error => &e.to_string());
                Err(StorageError::ReadFailed(e.to_string()))
            }
        }
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.db.put(key, value).map_err(StorageError::from)
    }
    fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        self.db.delete(key).map_err(StorageError::from)
    }
}

pub struct StorageManager {
    pub store: Arc<dyn KeyValueStore>,
}

impl StorageManager {
    /// Create a new StorageManager.
    ///
    /// For RocksDB backend: returns Err if the DB cannot be opened.
    /// A silent fallback to MemoryStore would cause consensus failure
    /// on mainnet — the node would run with ephemeral state and lose
    /// everything on restart, creating a network partition.
    pub fn new(backend: StorageBackend) -> Result<Self, StorageError> {
        let store: Arc<dyn KeyValueStore> = match backend {
            StorageBackend::Memory => Arc::new(MemoryStore::new()),
            StorageBackend::RocksDB(path) => {
                let rocks = RocksStore::new(&path)?;
                Arc::new(rocks)
            }
        };
        Ok(Self { store })
    }

    pub fn memory() -> Self {
        Self::new(StorageBackend::Memory).expect("MemoryStore creation cannot fail")
    }

    pub fn rocksdb(path: &str) -> Result<Self, StorageError> {
        Self::new(StorageBackend::RocksDB(path.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_put_get() {
        let store = MemoryStore::new();
        store.put(b"key", b"value").unwrap();
        assert_eq!(store.get(b"key").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn memory_store_delete() {
        let store = MemoryStore::new();
        store.put(b"k", b"v").unwrap();
        store.delete(b"k").unwrap();
        assert_eq!(store.get(b"k").unwrap(), None);
    }

    #[test]
    fn memory_store_exists() {
        let store = MemoryStore::new();
        assert!(!store.exists(b"x").unwrap());
        store.put(b"x", b"1").unwrap();
        assert!(store.exists(b"x").unwrap());
    }

    #[test]
    fn storage_manager_memory_backend() {
        let mgr = StorageManager::memory();
        mgr.store.put(b"hello", b"world").unwrap();
        assert_eq!(mgr.store.get(b"hello").unwrap(), Some(b"world".to_vec()));
    }
}
