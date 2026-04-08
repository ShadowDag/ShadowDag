// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// ContractStorage — Persistent storage with atomic WriteBatch support.
//
// All state changes during contract execution are buffered in a
// PendingBatch. On success, they are committed atomically via RocksDB
// WriteBatch. On failure (REVERT / OutOfGas), the batch is discarded
// and no state changes are persisted.
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteBatch};
use std::collections::BTreeMap;
use std::sync::Arc;
use serde::{Serialize, Deserialize};

use crate::errors::{VmError, StorageError};
use crate::infrastructure::storage::rocksdb::core::db::{open_shared_db, SharedDbSource};
use crate::slog_error;

// ═══════════════════════════════════════════════════════════════════════════
// CONTRACT UNDO DATA — block-level rollback support for reorg safety
// ═══════════════════════════════════════════════════════════════════════════

/// Block-level contract undo data for reorg rollback.
///
/// Captures every state mutation made during a block's contract execution
/// so that the changes can be reversed if the block is orphaned by a reorg.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractUndoData {
    /// Storage keys that were modified: (key, old_value or None if key was new)
    pub modified_keys: Vec<(String, Option<String>)>,
    /// Accounts created in this block
    pub created_accounts: Vec<String>,
    /// Accounts destroyed in this block (with full serialized account data for restore)
    pub destroyed_accounts: Vec<(String, String)>,
    /// Receipt root computed for this block
    pub receipt_root: Option<String>,
    /// State root computed for this block
    pub state_root: Option<String>,
}

/// Buffered state changes awaiting atomic commit
pub struct PendingBatch {
    /// Writes: key -> Some(value) for puts, key -> None for deletes
    changes: BTreeMap<String, Option<String>>,
}

impl Default for PendingBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingBatch {
    pub fn new() -> Self {
        Self {
            changes: BTreeMap::new(),
        }
    }

    /// Buffer a put operation
    pub fn put(&mut self, key: String, value: String) {
        self.changes.insert(key, Some(value));
    }

    /// Buffer a delete operation
    pub fn delete(&mut self, key: String) {
        self.changes.insert(key, None);
    }

    /// Number of pending changes
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Whether the batch is empty
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Discard all pending changes (on REVERT or OutOfGas)
    pub fn discard(&mut self) {
        self.changes.clear();
    }

    /// Consume the batch and return the changes for commit
    fn take_changes(&mut self) -> BTreeMap<String, Option<String>> {
        std::mem::take(&mut self.changes)
    }
}

pub struct ContractStorage {
    db:   Arc<DB>,
    path: String,
}

impl ContractStorage {
    pub fn new<S: Into<SharedDbSource>>(source: S) -> Result<Self, VmError> {
        let src: SharedDbSource = source.into();
        let path_str = match &src {
            SharedDbSource::Path(p) => p.to_string(),
            SharedDbSource::Shared(_) => "shared_db".to_string(),
        };
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = open_shared_db(src, &opts)
            .map_err(|e| VmError::Other(format!("ContractStorage init failed: {}", e)))?;
        Ok(Self { db, path: path_str })
    }

    /// Direct put (for non-batched operations like deployment metadata).
    ///
    /// Returns `Err(StorageError::WriteFailed)` if the underlying DB write fails.
    pub fn set_state(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let db_key = format!("contract:{}", key);
        self.db.put(db_key.as_bytes(), value.as_bytes())
            .map_err(|e| {
                slog_error!("runtime", "contract_storage_put_error", error => &e.to_string());
                StorageError::WriteFailed(e.to_string())
            })?;
        Ok(())
    }

    /// Direct get.
    ///
    /// Returns `None` only for genuine absence (key not found).
    /// Logs errors for read failures and UTF-8 corruption rather than
    /// silently conflating them with missing keys.
    pub fn get_state(&self, key: &str) -> Option<String> {
        let db_key = format!("contract:{}", key);
        match self.db.get(db_key.as_bytes()) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    slog_error!("runtime", "contract_state_utf8_corruption", key => key, error => &e.to_string());
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("runtime", "contract_state_read_failed", key => key, error => &e.to_string());
                None
            }
        }
    }

    /// Direct delete.
    ///
    /// Returns `Err(StorageError::WriteFailed)` if the underlying DB delete fails.
    pub fn delete_state(&self, key: &str) -> Result<(), StorageError> {
        let db_key = format!("contract:{}", key);
        self.db.delete(db_key.as_bytes())
            .map_err(|e| {
                slog_error!("runtime", "contract_delete_state_failed", key => key, error => &e.to_string());
                StorageError::WriteFailed(e.to_string())
            })?;
        Ok(())
    }

    /// Atomically commit a PendingBatch using RocksDB WriteBatch.
    ///
    /// All puts and deletes are applied in a single atomic operation.
    /// If ANY write fails, NONE of the changes are persisted.
    pub fn commit_batch(&self, batch: &mut PendingBatch) -> Result<(), VmError> {
        if batch.is_empty() {
            return Ok(());
        }

        let changes = batch.take_changes();
        let mut wb = WriteBatch::default();

        for (key, value) in &changes {
            let db_key = format!("contract:{}", key);
            match value {
                Some(v) => wb.put(db_key.as_bytes(), v.as_bytes()),
                None    => wb.delete(db_key.as_bytes()),
            }
        }

        self.db.write(wb).map_err(|e| VmError::Other(format!("WriteBatch commit failed: {}", e)))
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the underlying DB handle for sharing with sub-contexts
    pub fn shared_db(&self) -> Arc<DB> {
        Arc::clone(&self.db)
    }

    // ═══════════════════════════════════════════════════════════════════
    // UNDO DATA — block-level rollback for reorg safety
    // ═══════════════════════════════════════════════════════════════════

    /// Save undo data for a block so its contract state changes can be rolled back.
    pub fn save_undo(&self, block_hash: &str, undo: &ContractUndoData) -> Result<(), StorageError> {
        let key = format!("contract:undo:{}", block_hash);
        let data = bincode::serialize(undo)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.db.put(key.as_bytes(), &data)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    /// Load undo data for a block.
    pub fn load_undo(&self, block_hash: &str) -> Option<ContractUndoData> {
        let key = format!("contract:undo:{}", block_hash);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => bincode::deserialize(&data).ok(),
            _ => None,
        }
    }

    /// Check whether undo data exists for a block.
    pub fn has_undo_data(&self, block_hash: &str) -> bool {
        let key = format!("contract:undo:{}", block_hash);
        matches!(self.db.get(key.as_bytes()), Ok(Some(_)))
    }

    /// Rollback a block's contract state changes using its saved undo data.
    ///
    /// Restores modified keys to their pre-block values, removes accounts
    /// created during the block, and reinstates accounts destroyed during it.
    /// The undo record itself is deleted after successful rollback.
    pub fn rollback_block(&self, block_hash: &str) -> Result<(), StorageError> {
        let undo = self.load_undo(block_hash)
            .ok_or_else(|| StorageError::KeyNotFound(
                format!("no contract undo for {}", block_hash)
            ))?;

        let mut batch = WriteBatch::default();

        // Restore modified keys to their old values
        for (key, old_value) in &undo.modified_keys {
            let db_key = format!("contract:{}", key);
            match old_value {
                Some(val) => batch.put(db_key.as_bytes(), val.as_bytes()),
                None => batch.delete(db_key.as_bytes()), // key was new — delete it
            }
        }

        // Restore destroyed accounts
        for (addr, account_data) in &undo.destroyed_accounts {
            let db_key = format!("contract:account:{}", addr);
            batch.put(db_key.as_bytes(), account_data.as_bytes());
        }

        // Remove accounts created during this block
        for addr in &undo.created_accounts {
            let db_key = format!("contract:account:{}", addr);
            batch.delete(db_key.as_bytes());
            let code_key = format!("contract:code:{}", addr);
            batch.delete(code_key.as_bytes());
        }

        // Delete the undo record itself
        let undo_key = format!("contract:undo:{}", block_hash);
        batch.delete(undo_key.as_bytes());

        self.db.write(batch)
            .map_err(|e| StorageError::WriteFailed(
                format!("contract rollback failed: {}", e)
            ))
    }

    /// Prune undo data for finalized blocks (no longer needed for rollback).
    /// Returns the number of entries pruned.
    pub fn prune_finalized_undo_data(&self, block_hashes: &[String]) -> usize {
        let mut batch = WriteBatch::default();
        let mut count = 0;
        for hash in block_hashes {
            let key = format!("contract:undo:{}", hash);
            if matches!(self.db.get(key.as_bytes()), Ok(Some(_))) {
                batch.delete(key.as_bytes());
                count += 1;
            }
        }
        if count > 0 {
            if let Err(e) = self.db.write(batch) {
                slog_error!("runtime", "contract_undo_prune_failed", error => &e.to_string());
                return 0;
            }
        }
        count
    }
}
