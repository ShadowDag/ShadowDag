// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, IteratorMode, Options, WriteBatch};
use std::sync::Arc;

use crate::domain::transaction::transaction::Transaction;
use crate::domain::utxo::utxo::Utxo;
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_set::utxo_key;
use crate::errors::StorageError;
use crate::infrastructure::storage::rocksdb::core::db::{open_shared_db, SharedDbSource};
use crate::{slog_info, slog_error};

#[derive(Clone)]
pub struct UtxoStore {
    db: Arc<DB>,
}

impl UtxoStore {
    pub fn new<S: Into<SharedDbSource>>(source: S) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(64 * 1024 * 1024);

        let db = open_shared_db(source, &opts)?;

        Ok(Self { db })
    }

    pub fn raw_db(&self) -> &DB {
        self.db.as_ref()
    }

    pub fn add_utxo(&self, key: &UtxoKey, utxo: &Utxo) -> Result<(), StorageError> {
        let data = bincode::serialize(utxo)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        self.db
            .put(key.as_bytes(), &data)?;

        let mut addr_key = Vec::with_capacity(5 + utxo.address.len() + 1 + 36);
        addr_key.extend_from_slice(b"addr:");
        addr_key.extend_from_slice(utxo.address.as_bytes());
        addr_key.extend_from_slice(b":");
        addr_key.extend_from_slice(key.as_bytes());

        self.db
            .put(&addr_key, key.as_bytes())?;

        Ok(())
    }

    pub fn get_utxo(&self, key: &UtxoKey) -> Result<Option<Utxo>, StorageError> {
        let value = self
            .db
            .get(key.as_bytes())?;

        match value {
            Some(bytes) => {
                let utxo = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(utxo))
            }
            None => Ok(None),
        }
    }

    /// Atomically mark a UTXO as spent using a WriteBatch.
    ///
    /// The read-check-write is serialized by RocksDB's single-writer
    /// guarantee on `DB::write(batch)`. Callers at the consensus layer
    /// process blocks sequentially, so concurrent calls to spend_utxo
    /// with the same key cannot interleave between get and put.
    pub fn spend_utxo(&self, key: &UtxoKey) -> Result<(), StorageError> {
        let raw = self.db.get(key.as_bytes())?
            .ok_or_else(|| StorageError::KeyNotFound(key.to_string()))?;
        let mut utxo: Utxo = bincode::deserialize(&raw)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        if utxo.spent {
            return Err(StorageError::WriteFailed("utxo already spent".to_string()));
        }

        utxo.spent = true;
        let data = bincode::serialize(&utxo)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let mut batch = WriteBatch::default();
        batch.put(key.as_bytes(), &data);
        self.db.write(batch)?;
        Ok(())
    }

    pub fn exists(&self, key: &UtxoKey) -> Result<bool, StorageError> {
        Ok(self
            .db
            .get(key.as_bytes())?
            .is_some())
    }

    pub fn get_balance(&self, address: &str) -> Result<u64, StorageError> {
        let prefix = format!("addr:{}:", address);
        let iter = self.db.prefix_iterator(prefix.as_bytes());

        let mut balance: u64 = 0;

        for item in iter {
            let (k, v) = item?;

            if !k.starts_with(prefix.as_bytes()) {
                break;
            }

            if let Some(ukey) = UtxoKey::from_slice(&v) {
                if let Some(utxo) = self.get_utxo(&ukey)? {
                    if !utxo.spent {
                        balance = balance.saturating_add(utxo.amount);
                    }
                }
            }
        }

        Ok(balance)
    }

    pub fn apply_transaction(&self, tx: &Transaction) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();

        for input in &tx.inputs {
            let key = utxo_key(&input.txid, input.index)?;
            let mut utxo = self.get_utxo(&key)?
                .ok_or_else(|| StorageError::KeyNotFound(format!("input utxo {}", key)))?;

            if utxo.spent {
                return Err(StorageError::WriteFailed("double spend detected".to_string()));
            }

            utxo.spent = true;

            let data = bincode::serialize(&utxo)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            batch.put(key.as_bytes(), data);
        }

        for (i, output) in tx.outputs.iter().enumerate() {
            let key = utxo_key(&tx.hash, i as u32)?;

            let utxo = Utxo {
                owner: output.address.clone(),
                address: output.address.clone(),
                amount: output.amount,
                spent: false,
            };

            let data = bincode::serialize(&utxo)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            batch.put(key.as_bytes(), data);

            let mut addr_key = Vec::with_capacity(5 + output.address.len() + 1 + 36);
            addr_key.extend_from_slice(b"addr:");
            addr_key.extend_from_slice(output.address.as_bytes());
            addr_key.extend_from_slice(b":");
            addr_key.extend_from_slice(key.as_bytes());
            batch.put(&addr_key, key.as_bytes());
        }

        self.db.write(batch)?;
        Ok(())
    }

    pub fn export_all(&self) -> Result<Vec<(UtxoKey, Utxo)>, StorageError> {
        let iter = self.db.iterator(IteratorMode::Start);
        let mut result = Vec::new();

        for item in iter {
            let (k, v) = item?;

            // UTXO entries have exactly 36-byte binary keys
            if k.len() != 36 {
                continue;
            }

            if let Some(utxo_key) = UtxoKey::from_slice(&k) {
                match bincode::deserialize::<Utxo>(&v) {
                    Ok(utxo) if !utxo.spent => {
                        result.push((utxo_key, utxo));
                    }
                    Ok(_) => {} // spent — skip normally
                    Err(e) => {
                        slog_error!("storage", "utxo_export_corrupted_entry", key => utxo_key, error => e);
                    }
                }
            }
        }

        Ok(result)
    }

    /// Count total unspent UTXOs in the store.
    /// Used by crash recovery to detect if the UTXO set needs rebuilding.
    pub fn count_utxos(&self) -> usize {
        let iter = self.db.iterator(IteratorMode::Start);
        let mut count = 0;

        for item in iter {
            let (k, v) = match item {
                Ok(pair) => pair,
                Err(_) => continue,
            };

            if k.len() != 36 {
                continue;
            }

            if let Ok(u) = bincode::deserialize::<Utxo>(&v) {
                if !u.spent {
                    count += 1;
                }
            }
        }

        count
    }

    /// Clear UTXO-related data ONLY from the database. Used by crash recovery.
    ///
    /// SAFETY: Only deletes keys belonging to the UTXO subsystem:
    ///   - UTXO entries (36-byte binary keys that deserialize as Utxo)
    ///   - addr: index entries
    ///   - cb_height: coinbase maturity entries
    ///   - tx_seen: transaction uniqueness entries
    ///   - utxo:commitment: / utxo:undo: state entries
    ///
    /// Keys from other subsystems sharing the same DB are LEFT UNTOUCHED.
    pub fn clear_all(&self) {
        const UTXO_PREFIXES: &[&[u8]] = &[
            b"addr:",
            b"cb_height:",
            b"tx_seen:",
            b"utxo:commitment:",
            b"utxo:undo:",
            b"utxo:latest_commitment",
        ];

        let mut batch = rocksdb::WriteBatch::default();
        let mut count = 0usize;

        let iter = self.db.iterator(IteratorMode::Start);
        for (k, v) in iter.flatten() {
            let is_utxo_prefix = UTXO_PREFIXES.iter().any(|p| k.starts_with(p));
            let is_utxo_entry = k.len() == 36 && bincode::deserialize::<Utxo>(&v).is_ok();

            if is_utxo_prefix || is_utxo_entry {
                batch.delete(&k);
                count += 1;
            }
        }

        if count > 0 {
            if let Err(e) = self.db.write(batch) {
                slog_error!("storage", "utxo_clear_all_failed", keys => count, error => e);
            } else {
                slog_info!("storage", "utxo_clear_all_complete", keys => count);
            }
        }
    }

    /// Prune spent UTXOs from the database to reclaim disk space.
    /// Only deletes UTXOs where `spent == true`. Returns count pruned.
    pub fn prune_spent(&self) -> u64 {
        let mut batch = WriteBatch::default();
        let mut count = 0u64;

        let iter = self.db.iterator(IteratorMode::Start);
        for (k, v) in iter.flatten() {
            if k.len() != 36 {
                continue;
            }
            if let Ok(utxo) = bincode::deserialize::<Utxo>(&v) {
                if utxo.spent {
                    batch.delete(&k);
                    count += 1;
                    // Write in batches to limit memory
                    if count % 10_000 == 0 {
                        let _ = self.db.write(batch);
                        batch = WriteBatch::default();
                    }
                }
            }
        }
        if count % 10_000 != 0 {
            let _ = self.db.write(batch);
        }
        count
    }

    /// Compact the RocksDB to reclaim space after pruning
    pub fn compact(&self) {
        self.db.compact_range(None::<&[u8]>, None::<&[u8]>);
    }

    pub fn unspend_utxo(&self, key: &UtxoKey) -> Result<(), StorageError> {
        let mut utxo = self.get_utxo(key)?
            .ok_or_else(|| StorageError::KeyNotFound(key.to_string()))?;
        if utxo.amount == 0 {
            return Err(StorageError::WriteFailed(
                format!("refusing to restore zero-amount UTXO {}", key),
            ));
        }
        utxo.spent = false;
        self.add_utxo(key, &utxo)
    }
}

// ── Trait implementation ──────────────────────────────────────────────────
// UtxoStore implements the domain trait so that domain/ can depend on
// the abstract UtxoBackend instead of the concrete RocksDB type.

impl crate::domain::traits::utxo_backend::UtxoBackend for UtxoStore {
    fn add_utxo(&self, key: &UtxoKey, utxo: &Utxo) -> Result<(), StorageError> {
        self.add_utxo(key, utxo)
    }
    fn get_utxo(&self, key: &UtxoKey) -> Result<Option<Utxo>, StorageError> {
        self.get_utxo(key)
    }
    fn spend_utxo(&self, key: &UtxoKey) -> Result<(), StorageError> {
        self.spend_utxo(key)
    }
    fn exists(&self, key: &UtxoKey) -> Result<bool, StorageError> {
        self.exists(key)
    }
    fn get_balance(&self, address: &str) -> Result<u64, StorageError> {
        self.get_balance(address)
    }
    fn count_utxos(&self) -> usize {
        self.count_utxos()
    }
    fn clear_all(&self) {
        self.clear_all()
    }

    fn export_all(&self) -> Result<Vec<(UtxoKey, Utxo)>, StorageError> {
        self.export_all()
    }

    fn get_raw(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.db.get(key).ok().flatten().map(|v| v.to_vec())
    }

    fn put_raw(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.db.put(key, value).map_err(StorageError::from)
    }

    fn delete_raw(&self, key: &[u8]) -> Result<(), StorageError> {
        self.db.delete(key).map_err(StorageError::from)
    }

    fn write_batch(&self, ops: Vec<crate::domain::traits::utxo_backend::BatchWrite>) -> Result<(), StorageError> {
        use crate::domain::traits::utxo_backend::BatchWrite;
        let mut batch = WriteBatch::default();
        for op in ops {
            match op {
                BatchWrite::Put { key, value } => batch.put(&key, &value),
                BatchWrite::Delete { key } => batch.delete(&key),
            }
        }
        self.db.write(batch).map_err(StorageError::from)
    }

    fn prune_spent(&self) -> u64 {
        self.prune_spent()
    }

    fn compact(&self) {
        self.compact()
    }
}
