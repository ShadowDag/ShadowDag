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
    ///
    /// Returns `None` only for **genuine absence** of the undo key. A
    /// read error or a corrupt bincode payload is logged loudly via
    /// `slog_error!` with `may_be_false_negative` markers AND still
    /// returns `None` so existing callers don't break; if you need to
    /// distinguish "no undo" from "corrupt undo / read failed" — for
    /// example inside `rollback_block` or audit tooling — use
    /// [`Self::load_undo_strict`], which surfaces those cases as
    /// `Err(StorageError)`.
    ///
    /// The previous implementation used
    /// `bincode::deserialize(&data).ok()` and collapsed every
    /// corruption path and read error into `None`, which meant a reorg
    /// that tried to roll back a block with a damaged undo record
    /// would get `KeyNotFound("no contract undo …")` — a very
    /// misleading error that hid the real data-integrity problem.
    pub fn load_undo(&self, block_hash: &str) -> Option<ContractUndoData> {
        let key = format!("contract:undo:{}", block_hash);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match bincode::deserialize::<ContractUndoData>(&data) {
                Ok(undo) => Some(undo),
                Err(e) => {
                    slog_error!("runtime", "load_undo_deserialize_failed_may_be_false_negative",
                        block_hash => block_hash, error => &e.to_string(),
                        note => "returning None but undo record exists with corrupt bincode payload");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("runtime", "load_undo_read_failed_may_be_false_negative",
                    block_hash => block_hash, error => &e.to_string(),
                    note => "returning None but undo key may exist — this is a false negative");
                None
            }
        }
    }

    /// Strict variant of [`Self::load_undo`] that distinguishes the
    /// three possible states:
    ///
    ///   - `Ok(None)`            → undo key is genuinely absent
    ///   - `Ok(Some(undo))`      → undo key exists with a valid payload
    ///   - `Err(StorageError)` → read failed OR the payload is corrupt
    ///
    /// Reorg / rollback code should call this variant so that a
    /// corrupt undo record surfaces as a fatal error rather than being
    /// misreported as "no undo data available".
    pub fn load_undo_strict(
        &self,
        block_hash: &str,
    ) -> Result<Option<ContractUndoData>, StorageError> {
        let key = format!("contract:undo:{}", block_hash);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match bincode::deserialize::<ContractUndoData>(&data) {
                Ok(undo) => Ok(Some(undo)),
                Err(e) => {
                    slog_error!("runtime", "load_undo_deserialize_failed_strict",
                        block_hash => block_hash, error => &e.to_string());
                    Err(StorageError::Serialization(format!(
                        "contract undo for block '{}' is corrupt: {}",
                        block_hash, e
                    )))
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("runtime", "load_undo_read_failed_strict",
                    block_hash => block_hash, error => &e.to_string());
                Err(StorageError::ReadFailed(e.to_string()))
            }
        }
    }

    /// Check whether undo data exists for a block.
    ///
    /// Returns `true` only when the key is present AND its value is a
    /// valid `ContractUndoData` payload. A read error or a corrupt
    /// value is logged and reported as `false` — use
    /// [`Self::has_undo_data_strict`] to distinguish those cases from
    /// a genuine miss.
    pub fn has_undo_data(&self, block_hash: &str) -> bool {
        matches!(self.has_undo_data_strict(block_hash), Ok(true))
    }

    /// Strict variant of [`Self::has_undo_data`] that distinguishes
    /// "absent" from "read failed" and "corrupt payload".
    ///
    /// Returns:
    ///   - `Ok(true)`  → undo key exists with a valid payload
    ///   - `Ok(false)` → undo key is genuinely absent
    ///   - `Err(_)`    → read failure or payload corruption
    ///
    /// The previous `matches!(db.get(...), Ok(Some(_)))` check treated
    /// read errors identically to "no undo", and would claim a
    /// corrupt undo record exists even though `load_undo` would then
    /// return `None` — a liveness/consistency gap.
    pub fn has_undo_data_strict(&self, block_hash: &str) -> Result<bool, StorageError> {
        let key = format!("contract:undo:{}", block_hash);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => match bincode::deserialize::<ContractUndoData>(&data) {
                Ok(_) => Ok(true),
                Err(e) => {
                    slog_error!("runtime", "has_undo_data_corrupt_payload",
                        block_hash => block_hash, error => &e.to_string());
                    Err(StorageError::Serialization(format!(
                        "contract undo for block '{}' is corrupt: {}",
                        block_hash, e
                    )))
                }
            },
            Ok(None) => Ok(false),
            Err(e) => {
                slog_error!("runtime", "has_undo_data_read_failed",
                    block_hash => block_hash, error => &e.to_string());
                Err(StorageError::ReadFailed(e.to_string()))
            }
        }
    }

    /// Rollback a block's contract state changes using its saved undo data.
    ///
    /// Restores modified keys to their pre-block values, removes accounts
    /// created during the block, and reinstates accounts destroyed during it.
    /// The undo record itself is deleted after successful rollback.
    ///
    /// Fail-closed on corruption: uses `load_undo_strict`, so a damaged
    /// undo record produces a structured error instead of being
    /// misreported as "no undo data available".
    pub fn rollback_block(&self, block_hash: &str) -> Result<(), StorageError> {
        let undo = self
            .load_undo_strict(block_hash)?
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
    ///
    /// Returns the number of entries successfully deleted. A return of
    /// `0` is **ambiguous** on its own — it may mean "nothing matched"
    /// or "write failed during pruning". Callers that need to tell the
    /// two cases apart must use [`Self::prune_finalized_undo_data_strict`]
    /// which returns a `Result` surfacing the write failure.
    pub fn prune_finalized_undo_data(&self, block_hashes: &[String]) -> usize {
        self.prune_finalized_undo_data_strict(block_hashes)
            .unwrap_or_else(|e| {
                slog_error!("runtime", "contract_undo_prune_failed_returning_zero",
                    error => &e.to_string(),
                    note => "returning 0 which is indistinguishable from 'nothing to prune' — use prune_finalized_undo_data_strict to distinguish");
                0
            })
    }

    /// Strict variant of [`Self::prune_finalized_undo_data`] that
    /// distinguishes three outcomes:
    ///
    /// - `Ok(0)` → none of the requested blocks had undo records
    /// - `Ok(n)` → `n` undo records were atomically deleted
    /// - `Err(_)` → a read or write error aborted the prune; no
    ///   records were deleted
    ///
    /// Read errors on the existence probe are now surfaced as well.
    /// The non-strict version silently skipped them (treating
    /// "read failed" the same as "no undo here"), which caused
    /// maintenance-stat counters to under-report the real work done.
    pub fn prune_finalized_undo_data_strict(
        &self,
        block_hashes: &[String],
    ) -> Result<usize, StorageError> {
        let mut batch = WriteBatch::default();
        let mut count = 0usize;

        for hash in block_hashes {
            let key = format!("contract:undo:{}", hash);
            match self.db.get(key.as_bytes()) {
                Ok(Some(_)) => {
                    batch.delete(key.as_bytes());
                    count += 1;
                }
                Ok(None) => {
                    // Nothing to delete for this hash — fine.
                }
                Err(e) => {
                    slog_error!("runtime", "prune_undo_probe_failed",
                        block_hash => hash, error => &e.to_string());
                    return Err(StorageError::ReadFailed(format!(
                        "prune probe for block '{}' failed: {}",
                        hash, e
                    )));
                }
            }
        }

        if count > 0 {
            self.db.write(batch).map_err(|e| {
                slog_error!("runtime", "contract_undo_prune_write_failed",
                    error => &e.to_string());
                StorageError::WriteFailed(format!("contract undo prune write failed: {}", e))
            })?;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_storage() -> ContractStorage {
        let dir = std::env::temp_dir().join(format!(
            "shadowdag_contract_storage_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        ContractStorage::new(dir.to_str().unwrap()).expect("open ContractStorage")
    }

    fn sample_undo() -> ContractUndoData {
        ContractUndoData {
            modified_keys: vec![
                ("account:SD1abc".to_string(), Some("10|1|xxx".to_string())),
            ],
            created_accounts: vec!["SD1new".to_string()],
            destroyed_accounts: vec![],
            receipt_root: None,
            state_root: None,
        }
    }

    #[test]
    fn save_and_load_undo_roundtrip() {
        let s = tmp_storage();
        let undo = sample_undo();
        s.save_undo("block_hash_1", &undo).unwrap();
        let loaded = s.load_undo("block_hash_1").unwrap();
        assert_eq!(loaded.created_accounts, vec!["SD1new".to_string()]);
    }

    #[test]
    fn load_undo_strict_distinguishes_missing_from_corrupt() {
        let s = tmp_storage();

        // Genuine miss → Ok(None), not Err.
        assert!(matches!(s.load_undo_strict("absent"), Ok(None)));

        // Corrupt payload → Err (not None).
        s.db
            .put(b"contract:undo:corrupt_block", b"this-is-not-bincode")
            .expect("raw put");

        // Non-strict masks corruption as None (with log)
        assert!(s.load_undo("corrupt_block").is_none());
        // Strict surfaces it as Err
        assert!(s.load_undo_strict("corrupt_block").is_err());
    }

    #[test]
    fn has_undo_data_strict_distinguishes_missing_from_corrupt() {
        let s = tmp_storage();

        // Absent key → Ok(false)
        assert!(matches!(s.has_undo_data_strict("absent"), Ok(false)));

        // Valid undo → Ok(true)
        let undo = sample_undo();
        s.save_undo("block_present", &undo).unwrap();
        assert!(matches!(s.has_undo_data_strict("block_present"), Ok(true)));

        // Corrupt payload → Err
        s.db
            .put(b"contract:undo:bad_block", b"not-bincode")
            .expect("raw put");
        assert!(s.has_undo_data_strict("bad_block").is_err());
        // Non-strict maps corruption to false (old behaviour's closest
        // compat — `has_undo_data` asked "does a USABLE undo exist?")
        assert!(!s.has_undo_data("bad_block"));
    }

    #[test]
    fn rollback_block_fails_closed_on_corrupt_undo() {
        let s = tmp_storage();
        // Plant raw garbage under the undo key, then try to roll back.
        // Previously load_undo returned None and rollback_block reported
        // KeyNotFound — now it must surface the corruption.
        s.db
            .put(b"contract:undo:corrupt_rollback", b"garbage")
            .expect("raw put");
        let result = s.rollback_block("corrupt_rollback");
        assert!(result.is_err(), "rollback must fail on corrupt undo, not treat it as missing");
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("corrupt") || msg.contains("Serialization"),
            "expected corruption error, got: {}",
            msg
        );
    }

    #[test]
    fn prune_finalized_undo_strict_reports_count_and_surfaces_errors() {
        let s = tmp_storage();
        let undo = sample_undo();
        s.save_undo("a", &undo).unwrap();
        s.save_undo("b", &undo).unwrap();

        let count = s
            .prune_finalized_undo_data_strict(&[
                "a".to_string(),
                "b".to_string(),
                "absent".to_string(),
            ])
            .unwrap();
        assert_eq!(count, 2, "should prune the 2 existing blocks and skip the absent one");

        // After pruning, the records should actually be gone.
        assert!(matches!(s.has_undo_data_strict("a"), Ok(false)));
        assert!(matches!(s.has_undo_data_strict("b"), Ok(false)));
    }

    #[test]
    fn prune_finalized_undo_non_strict_returns_zero_on_write_failure_but_logs() {
        // We can't easily simulate a RocksDB write failure in-process, so
        // this test just verifies that a clean "nothing to prune" call
        // returns Ok(0) on the strict path (and 0 on the non-strict).
        let s = tmp_storage();
        let count = s.prune_finalized_undo_data_strict(&["nonexistent".to_string()]).unwrap();
        assert_eq!(count, 0);
        assert_eq!(s.prune_finalized_undo_data(&["nonexistent".to_string()]), 0);
    }
}
