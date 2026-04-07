// =============================================================================
//                           S H A D O W D A G
//                     (c) ShadowDAG Project -- All Rights Reserved
// =============================================================================

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use rocksdb::DB;
use crate::domain::utxo::utxo_set::utxo_key;
use crate::{slog_info, slog_warn, slog_error};

const PREFIX: &str = "uidx:";
const ADDR_PREFIX: &str = "uidx:addr:";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UtxoRecord {
    pub txid:       String,
    pub vout:       u32,
    pub address:    String,
    pub amount:     u64,
    pub block_hash: String,
    pub height:     u64,
    pub is_spent:   bool,
}

impl UtxoRecord {
    pub fn key(&self) -> Result<String, crate::errors::StorageError> {
        Ok(utxo_key(&self.txid, self.vout)?.to_string())
    }
}

pub struct UtxoIndex {
    utxos:           HashMap<String, UtxoRecord>,
    addr_index:      HashMap<String, HashSet<String>>,
    pub total_utxos:     u64,
    pub spent_utxos:     u64,
    db:              Arc<DB>,
}

impl Default for UtxoIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl UtxoIndex {
    /// Open a UtxoIndex with a temp DB.  Returns Result instead of panicking.
    ///
    /// Prefer `new_with_db` for shared-DB setups in production.
    pub fn try_new() -> Result<Self, crate::errors::StorageError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let unique = format!("shadowdag_uidx_{}_{:?}",
            std::process::id(), std::thread::current().id());
        let tmp = std::env::temp_dir().join(unique);
        let db = DB::open(&opts, &tmp)
            .map_err(|e| crate::errors::StorageError::OpenFailed {
                path: tmp.to_string_lossy().to_string(),
                reason: e.to_string(),
            })?;
        Ok(Self {
            utxos:       HashMap::new(),
            addr_index:  HashMap::new(),
            total_utxos: 0,
            spent_utxos: 0,
            db:          Arc::new(db),
        })
    }

    /// Legacy constructor — calls try_new and logs on failure.
    ///
    /// Panics only as a last resort (OS-level /tmp failure).
    /// Tests and non-critical paths may use this; production should
    /// prefer `new_with_db` or `try_new`.
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|e| {
            slog_warn!("index", "utxo_index_db_open_failed", error => &e.to_string());
            let fallback = std::env::temp_dir().join(format!(
                "shadowdag_uidx_fb_{}", std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos()
            ));
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            let db = DB::open(&opts, &fallback).unwrap_or_else(|e2| {
                slog_error!("index", "utxo_index_fallback_failed", error => &e2.to_string());
                let noop = std::env::temp_dir().join("shadowdag_uidx_noop");
                let _ = std::fs::create_dir_all(&noop);
                match DB::open(&opts, &noop) {
                    Ok(db) => db,
                    Err(e3) => {
                        slog_error!("index", "utxo_index_fatal_abort", error => &e3.to_string());
                        std::process::abort();
                    }
                }
            });
            Self {
                utxos:       HashMap::new(),
                addr_index:  HashMap::new(),
                total_utxos: 0,
                spent_utxos: 0,
                db:          Arc::new(db),
            }
        })
    }

    /// Construct with a shared RocksDB instance (production path).
    /// Automatically recovers state from DB so the caller cannot forget.
    pub fn new_with_db(db: Arc<DB>) -> Self {
        let mut s = Self {
            utxos:       HashMap::new(),
            addr_index:  HashMap::new(),
            total_utxos: 0,
            spent_utxos: 0,
            db,
        };
        s.recover_from_db();
        slog_info!("index", "utxo_index_recovered", utxos => &s.total_utxos.to_string());
        s
    }

    // ── helpers ───────────────────────────────────────────────

    fn db_key(key: &str) -> Vec<u8> {
        format!("{}{}", PREFIX, key).into_bytes()
    }

    fn db_addr_key(addr: &str) -> Vec<u8> {
        format!("{}{}", ADDR_PREFIX, addr).into_bytes()
    }

    fn write_record_to_db(&self, utxo: &UtxoRecord) {
        let utxo_key = match utxo.key() {
            Ok(k) => k,
            Err(e) => { slog_error!("index", "bad_utxo_key", error => &e.to_string()); return; }
        };
        let key = Self::db_key(&utxo_key);
        let val = match serde_json::to_vec(utxo) {
            Ok(v) => v,
            Err(e) => {
                slog_error!("index", "utxo_index_serialize_error", error => &e.to_string());
                return;
            }
        };
        if let Err(e) = self.db.put(&key, &val) {
            slog_error!("index", "utxo_index_db_put_error", error => &e.to_string());
        }
    }

    fn delete_record_from_db(&self, utxo_key: &str) {
        let key = Self::db_key(utxo_key);
        if let Err(e) = self.db.delete(&key) {
            slog_error!("index", "utxo_index_db_delete_error", error => &e.to_string());
        }
    }

    /// Persist the addr -> keys set to DB.
    fn write_addr_set_to_db(&self, addr: &str) {
        let db_key = Self::db_addr_key(addr);
        if let Some(set) = self.addr_index.get(addr) {
            let val = match serde_json::to_vec(set) {
                Ok(v) => v,
                Err(e) => {
                    slog_error!("index", "utxo_index_addr_set_serialize_error", error => &e.to_string());
                    return;
                }
            };
            if let Err(e) = self.db.put(&db_key, &val) {
                slog_error!("index", "utxo_index_addr_set_put_error", error => &e.to_string());
            }
        } else {
            if let Err(e) = self.db.delete(&db_key) {
                slog_error!("index", "utxo_index_addr_set_delete_error", error => &e.to_string());
            }
        }
    }

    fn load_record_from_db(&self, utxo_key: &str) -> Option<UtxoRecord> {
        let key = Self::db_key(utxo_key);
        match self.db.get(&key) {
            Ok(Some(data)) => serde_json::from_slice(&data).ok(),
            _ => None,
        }
    }

    // ── public API ───────────────────────────────────────────

    pub fn insert(&mut self, utxo: UtxoRecord) {
        let key = match utxo.key() {
            Ok(k) => k,
            Err(e) => { slog_error!("index", "insert_bad_utxo_key", error => &e.to_string()); return; }
        };
        let addr = utxo.address.clone();

        // Persist to RocksDB first
        self.write_record_to_db(&utxo);

        self.addr_index
            .entry(addr.clone())
            .or_default()
            .insert(key.clone());
        self.write_addr_set_to_db(&addr);

        self.utxos.insert(key, utxo);
        self.total_utxos += 1;
    }

    pub fn mark_spent(&mut self, key: &str) -> bool {
        // Try cache first
        if let Some(utxo) = self.utxos.get_mut(key) {
            if !utxo.is_spent {
                utxo.is_spent = true;
                self.spent_utxos += 1;
                let cloned = utxo.clone();
                self.write_record_to_db(&cloned);
                return true;
            }
            return false;
        }
        // Fallback to DB
        if let Some(mut utxo) = self.load_record_from_db(key) {
            if !utxo.is_spent {
                utxo.is_spent = true;
                self.spent_utxos += 1;
                self.write_record_to_db(&utxo);
                self.utxos.insert(key.to_string(), utxo);
                return true;
            }
        }
        false
    }

    pub fn remove(&mut self, key: &str) -> bool {
        // Remove from DB regardless
        self.delete_record_from_db(key);

        if let Some(utxo) = self.utxos.remove(key) {
            if let Some(set) = self.addr_index.get_mut(&utxo.address) {
                set.remove(key);
                if set.is_empty() {
                    self.addr_index.remove(&utxo.address);
                }
            }
            self.write_addr_set_to_db(&utxo.address);
            self.total_utxos = self.total_utxos.saturating_sub(1);
            if utxo.is_spent {
                self.spent_utxos = self.spent_utxos.saturating_sub(1);
            }
            return true;
        }
        // Even if not in cache, check DB
        if let Some(utxo) = self.load_record_from_db(key) {
            self.delete_record_from_db(key);
            // Clean addr set in DB
            self.write_addr_set_to_db(&utxo.address);
            self.total_utxos = self.total_utxos.saturating_sub(1);
            if utxo.is_spent {
                self.spent_utxos = self.spent_utxos.saturating_sub(1);
            }
            return true;
        }
        false
    }

    pub fn get(&self, key: &str) -> Option<&UtxoRecord> {
        self.utxos.get(key)
    }

    /// Get from cache first, then fall back to RocksDB.
    /// Returns an owned record when loaded from DB.
    pub fn get_or_load(&mut self, key: &str) -> Option<&UtxoRecord> {
        if self.utxos.contains_key(key) {
            return self.utxos.get(key);
        }
        if let Some(rec) = self.load_record_from_db(key) {
            self.utxos.insert(key.to_string(), rec);
            return self.utxos.get(key);
        }
        None
    }

    pub fn is_spent(&self, key: &str) -> bool {
        if let Some(u) = self.utxos.get(key) {
            return u.is_spent;
        }
        // Fallback
        let db_key = Self::db_key(key);
        if let Ok(Some(data)) = self.db.get(&db_key) {
            if let Ok(rec) = serde_json::from_slice::<UtxoRecord>(&data) {
                return rec.is_spent;
            }
        }
        false
    }

    pub fn contains(&self, key: &str) -> bool {
        if self.utxos.contains_key(key) {
            return true;
        }
        let db_key = Self::db_key(key);
        matches!(self.db.get(&db_key), Ok(Some(_)))
    }

    pub fn balance(&self, address: &str) -> u64 {
        self.addr_index.get(address)
            .map(|keys| {
                let mut sum = 0u64;
                for k in keys {
                    if let Some(u) = self.utxos.get(k) {
                        if !u.is_spent {
                            match sum.checked_add(u.amount) {
                                Some(v) => sum = v,
                                None => {
                                    slog_warn!("index", "balance_overflow", address => address);
                                    return sum; // return partial sum before overflow
                                }
                            }
                        }
                    }
                }
                sum
            })
            .unwrap_or(0)
    }

    pub fn utxos_for_address(&self, address: &str) -> Vec<&UtxoRecord> {
        self.addr_index.get(address)
            .map(|keys| keys.iter()
                .filter_map(|k| self.utxos.get(k))
                .filter(|u| !u.is_spent)
                .collect())
            .unwrap_or_default()
    }

    pub fn unspent_count(&self) -> usize {
        self.utxos.values().filter(|u| !u.is_spent).count()
    }

    pub fn address_count(&self) -> usize { self.addr_index.len() }

    pub fn total_supply(&self) -> u64 {
        let mut sum = 0u64;
        for u in self.utxos.values().filter(|u| !u.is_spent) {
            match sum.checked_add(u.amount) {
                Some(v) => sum = v,
                None => {
                    slog_warn!("index", "total_supply_overflow");
                    return sum; // return partial sum before overflow
                }
            }
        }
        sum
    }

    pub fn rollback_block(&mut self, block_hash: &str) -> usize {
        let to_remove: Vec<String> = self.utxos.values()
            .filter(|u| u.block_hash == block_hash)
            .filter_map(|u| u.key().ok())
            .collect();
        let count = to_remove.len();
        for key in to_remove { self.remove(&key); }
        count
    }

    /// Rebuild the in-memory cache from RocksDB on startup.
    pub fn recover_from_db(&mut self) {
        let prefix = PREFIX.as_bytes();
        let addr_prefix = ADDR_PREFIX.as_bytes();
        let iter = self.db.prefix_iterator(prefix);

        self.utxos.clear();
        self.addr_index.clear();
        self.total_utxos = 0;
        self.spent_utxos = 0;

        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };

            // Skip addr-set keys (they start with "uidx:addr:")
            if key.starts_with(addr_prefix) {
                continue;
            }
            // Only process keys that start with our prefix
            if !key.starts_with(prefix) {
                break; // prefix_iterator is ordered; once we leave the prefix, stop
            }

            if let Ok(rec) = serde_json::from_slice::<UtxoRecord>(&value) {
                let utxo_key = match rec.key() {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                let addr = rec.address.clone();
                if rec.is_spent {
                    self.spent_utxos += 1;
                }
                self.addr_index
                    .entry(addr)
                    .or_default()
                    .insert(utxo_key.clone());
                self.utxos.insert(utxo_key, rec);
                self.total_utxos += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convert a short test name to a deterministic 64-char hex hash.
    fn th(name: &str) -> String {
        use sha2::{Sha256, Digest};
        hex::encode(Sha256::digest(name.as_bytes()))
    }

    fn utxo_key_str(txid: &str, vout: u32) -> String {
        crate::domain::utxo::utxo_set::utxo_key(&th(txid), vout)
            .expect("test hash must be valid")
            .to_string()
    }

    fn utxo(txid: &str, vout: u32, addr: &str, amount: u64) -> UtxoRecord {
        UtxoRecord {
            txid:       th(txid),
            vout,
            address:    addr.to_string(),
            amount,
            block_hash: "block1".into(),
            height:     1,
            is_spent:   false,
        }
    }

    #[test]
    fn insert_and_balance() {
        let mut idx = UtxoIndex::new();
        idx.insert(utxo("tx1", 0, "addr1", 1_000_000));
        assert_eq!(idx.balance("addr1"), 1_000_000);
    }

    #[test]
    fn mark_spent_reduces_balance() {
        let mut idx = UtxoIndex::new();
        idx.insert(utxo("tx1", 0, "addr1", 1_000_000));
        idx.mark_spent(&utxo_key_str("tx1", 0));
        assert_eq!(idx.balance("addr1"), 0);
    }

    #[test]
    fn is_spent_correct() {
        let mut idx = UtxoIndex::new();
        idx.insert(utxo("tx2", 0, "addr2", 500));
        assert!(!idx.is_spent(&utxo_key_str("tx2", 0)));
        idx.mark_spent(&utxo_key_str("tx2", 0));
        assert!(idx.is_spent(&utxo_key_str("tx2", 0)));
    }

    #[test]
    fn utxos_for_address_returns_unspent() {
        let mut idx = UtxoIndex::new();
        idx.insert(utxo("t1", 0, "alice", 1000));
        idx.insert(utxo("t2", 0, "alice", 2000));
        idx.mark_spent(&utxo_key_str("t1", 0));
        let unspent = idx.utxos_for_address("alice");
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].txid, th("t2"));
    }

    #[test]
    fn rollback_removes_block_utxos() {
        let mut idx = UtxoIndex::new();
        idx.insert(utxo("tx_b", 0, "addr", 9999));
        let removed = idx.rollback_block("block1");
        assert_eq!(removed, 1);
        assert!(!idx.contains(&utxo_key_str("tx_b", 0)));
    }

    #[test]
    fn total_supply_sums_unspent() {
        let mut idx = UtxoIndex::new();
        idx.insert(utxo("t1", 0, "a", 1000));
        idx.insert(utxo("t2", 0, "b", 2000));
        assert_eq!(idx.total_supply(), 3000);
    }

    #[test]
    fn recover_from_db_rebuilds_cache() {
        let mut idx = UtxoIndex::new();
        idx.insert(utxo("rx1", 0, "bob", 5000));
        idx.insert(utxo("rx2", 1, "bob", 3000));
        idx.mark_spent(&utxo_key_str("rx1", 0));

        // Clone DB arc before clearing cache
        let db = Arc::clone(&idx.db);

        // Simulate restart: create new index with same DB
        let mut idx2 = UtxoIndex::new_with_db(db);
        idx2.recover_from_db();

        assert!(idx2.contains(&utxo_key_str("rx1", 0)));
        assert!(idx2.contains(&utxo_key_str("rx2", 1)));
        assert!(idx2.is_spent(&utxo_key_str("rx1", 0)));
        assert_eq!(idx2.balance("bob"), 3000);
        assert_eq!(idx2.total_utxos, 2);
        assert_eq!(idx2.spent_utxos, 1);
    }
}
