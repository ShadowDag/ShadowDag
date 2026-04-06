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

use crate::errors::VmError;
use crate::infrastructure::storage::rocksdb::core::db::{open_shared_db, SharedDbSource};
use crate::slog_error;

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

    /// Direct put (for non-batched operations like deployment metadata)
    pub fn set_state(&self, key: &str, value: &str) {
        let db_key = format!("contract:{}", key);
        if let Err(e) = self.db.put(db_key.as_bytes(), value.as_bytes()) {
            slog_error!("runtime", "contract_storage_put_error", error => &e.to_string());
        }
    }

    /// Direct get
    pub fn get_state(&self, key: &str) -> Option<String> {
        let db_key = format!("contract:{}", key);
        match self.db.get(db_key.as_bytes()) {
            Ok(Some(data)) => String::from_utf8(data.to_vec()).ok(),
            Ok(None) => None,
            Err(e) => {
                slog_error!("runtime", "contract_storage_get_error", key => key, error => &e.to_string());
                None
            }
        }
    }

    /// Direct delete
    pub fn delete_state(&self, key: &str) {
        let db_key = format!("contract:{}", key);
        let _ = self.db.delete(db_key.as_bytes());
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
}
