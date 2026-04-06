// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// State Store — General-purpose key-value state storage for smart contracts,
// account balances, and any deterministic state that needs to be committed.
//
// Features:
//   - Contract-isolated storage (sandboxing)
//   - State root computation (Merkle hash of all state)
//   - Atomic batch updates (WriteBatch)
//   - State snapshots for rollback
//   - Iteration with prefix filtering
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteBatch};
use std::path::Path;
use std::sync::Arc;
use sha2::{Sha256, Digest};

use crate::errors::StorageError;

/// Prefix for contract state keys
const PFX_STATE:    &str = "state:";
/// Prefix for state root
const PFX_ROOT:     &str = "stateroot:";

pub struct StateStore {
    db: Arc<DB>,
}

impl StateStore {
    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(64 * 1024 * 1024); // 64 MB
        opts.set_max_write_buffer_number(3);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Set a state value for a contract
    pub fn set(&self, contract: &str, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let db_key = format!("{}{}/{}", PFX_STATE, contract, key);
        self.db.put(db_key.as_bytes(), value)?;
        Ok(())
    }

    /// Get a state value for a contract
    pub fn get(&self, contract: &str, key: &str) -> Option<Vec<u8>> {
        let db_key = format!("{}{}/{}", PFX_STATE, contract, key);
        self.db.get(db_key.as_bytes()).unwrap_or(None).map(|v| v.to_vec())
    }

    /// Delete a state key
    pub fn delete(&self, contract: &str, key: &str) -> Result<(), StorageError> {
        let db_key = format!("{}{}/{}", PFX_STATE, contract, key);
        self.db.delete(db_key.as_bytes())?;
        Ok(())
    }

    /// Apply a batch of state changes atomically
    pub fn apply_batch(&self, changes: &[(String, String, Vec<u8>)]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        for (contract, key, value) in changes {
            let db_key = format!("{}{}/{}", PFX_STATE, contract, key);
            batch.put(db_key.as_bytes(), value);
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Compute the state root (Merkle hash of all state entries)
    pub fn compute_state_root(&self) -> String {
        let prefix = PFX_STATE.as_bytes();
        let iter = self.db.prefix_iterator(prefix);

        let mut hashes: Vec<Vec<u8>> = Vec::new();

        for (k, v) in iter.flatten() {
            let k_str = String::from_utf8_lossy(&k);
            if !k_str.starts_with(PFX_STATE) { break; }

            let mut h = Sha256::new();
            h.update(&k);
            h.update(&v);
            hashes.push(h.finalize().to_vec());
        }

        if hashes.is_empty() {
            return "0".repeat(64);
        }

        // Merkle tree
        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 {
                hashes.push(hashes.last().cloned().unwrap_or_default());
            }
            hashes = hashes.chunks(2).map(|pair| {
                let mut h = Sha256::new();
                h.update(b"ShadowDAG_StateRoot_v1");
                h.update(&pair[0]);
                h.update(&pair[1]);
                h.finalize().to_vec()
            }).collect();
        }

        hex::encode(&hashes[0])
    }

    /// Save the current state root at a given height
    pub fn commit_state_root(&self, height: u64) -> Result<String, StorageError> {
        let root = self.compute_state_root();
        let key = format!("{}{}", PFX_ROOT, height);
        self.db.put(key.as_bytes(), root.as_bytes())?;
        Ok(root)
    }

    /// Get the state root at a given height
    pub fn get_state_root(&self, height: u64) -> Option<String> {
        let key = format!("{}{}", PFX_ROOT, height);
        self.db.get(key.as_bytes()).unwrap_or(None)
            .map(|v| String::from_utf8(v.to_vec()).unwrap_or_default())
    }

    /// Get all keys for a contract
    pub fn get_contract_keys(&self, contract: &str) -> Vec<String> {
        let prefix = format!("{}{}/", PFX_STATE, contract);
        let iter = self.db.prefix_iterator(prefix.as_bytes());

        let mut keys = Vec::new();
        for (k, _) in iter.flatten() {
            let k_str = String::from_utf8_lossy(&k).to_string();
            if !k_str.starts_with(&prefix) { break; }
            let key = k_str[prefix.len()..].to_string();
            keys.push(key);
        }
        keys
    }

    /// Delete all state for a contract (used for SELFDESTRUCT)
    pub fn clear_contract(&self, contract: &str) -> Result<usize, StorageError> {
        let keys = self.get_contract_keys(contract);
        let count = keys.len();
        let mut batch = WriteBatch::default();
        for key in &keys {
            let db_key = format!("{}{}/{}", PFX_STATE, contract, key);
            batch.delete(db_key.as_bytes());
        }
        self.db.write(batch)?;
        Ok(count)
    }

    /// Get the underlying DB reference
    pub fn raw_db(&self) -> &DB { &self.db }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> StateStore {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        StateStore::new(&format!("/tmp/test_state_{}", ts)).unwrap()
    }

    #[test]
    fn set_and_get() {
        let store = make_store();
        store.set("contract1", "balance", b"1000").unwrap();
        let val = store.get("contract1", "balance").unwrap();
        assert_eq!(val, b"1000");
    }

    #[test]
    fn get_missing_returns_none() {
        let store = make_store();
        assert!(store.get("c", "missing").is_none());
    }

    #[test]
    fn delete_removes_key() {
        let store = make_store();
        store.set("c", "k", b"v").unwrap();
        store.delete("c", "k").unwrap();
        assert!(store.get("c", "k").is_none());
    }

    #[test]
    fn batch_applies_atomically() {
        let store = make_store();
        let changes = vec![
            ("c1".into(), "a".into(), b"1".to_vec()),
            ("c1".into(), "b".into(), b"2".to_vec()),
            ("c2".into(), "x".into(), b"3".to_vec()),
        ];
        store.apply_batch(&changes).unwrap();
        assert_eq!(store.get("c1", "a").unwrap(), b"1");
        assert_eq!(store.get("c2", "x").unwrap(), b"3");
    }

    #[test]
    fn state_root_deterministic() {
        let store = make_store();
        store.set("c", "k1", b"v1").unwrap();
        store.set("c", "k2", b"v2").unwrap();
        let r1 = store.compute_state_root();
        let r2 = store.compute_state_root();
        assert_eq!(r1, r2);
        assert_eq!(r1.len(), 64);
    }

    #[test]
    fn commit_and_retrieve_state_root() {
        let store = make_store();
        store.set("c", "k", b"v").unwrap();
        let root = store.commit_state_root(100).unwrap();
        let retrieved = store.get_state_root(100).unwrap();
        assert_eq!(root, retrieved);
    }

    #[test]
    fn contract_isolation() {
        let store = make_store();
        store.set("alice", "balance", b"100").unwrap();
        store.set("bob", "balance", b"200").unwrap();
        assert_eq!(store.get("alice", "balance").unwrap(), b"100");
        assert_eq!(store.get("bob", "balance").unwrap(), b"200");
    }

    #[test]
    fn clear_contract_removes_all() {
        let store = make_store();
        store.set("dead", "k1", b"v1").unwrap();
        store.set("dead", "k2", b"v2").unwrap();
        store.set("alive", "k1", b"keep").unwrap();

        let removed = store.clear_contract("dead").unwrap();
        assert_eq!(removed, 2);
        assert!(store.get("dead", "k1").is_none());
        assert!(store.get("alive", "k1").is_some());
    }
}
