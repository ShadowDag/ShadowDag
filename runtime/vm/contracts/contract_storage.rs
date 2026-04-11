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

/// Full record of a destroyed account, including its code and storage,
/// so that a reorg can fully re-materialize everything the SELFDESTRUCT
/// removed — not just the account metadata row.
///
/// Serialized as a JSON string and stored inside
/// [`ContractUndoData::destroyed_accounts`]'s second tuple element. This
/// keeps the on-disk bincode layout of `ContractUndoData` unchanged (the
/// field is still `Vec<(String, String)>`), so pending undo records
/// written before this patch still deserialize. The reader side in
/// [`ContractStorage::rollback_block`] tries `serde_json::from_str`
/// first, and falls back to the legacy "pipe-delimited account metadata"
/// format when the string is not valid JSON.
///
/// The legacy format stored only `"balance|nonce|code_hash"` and could
/// therefore only restore the account row; a SELFDESTRUCT'd contract's
/// code bytes and storage slots were silently lost after a reorg. This
/// new format carries all three.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroyedAccountDetails {
    /// Account metadata row in the legacy `"balance|nonce|code_hash"`
    /// format, exactly as persisted under `contract:account:{addr}`.
    pub meta: String,
    /// Hex-encoded contract code that was previously stored under
    /// `contract:code:{addr}`. `None` for externally-owned accounts
    /// with no code (which should not normally be destroyed, but
    /// we track the `Option` for completeness).
    pub code: Option<String>,
    /// Every pre-destroy storage slot under this contract, as
    /// `(slot_key_suffix, value)` pairs. The `slot_key_suffix` is the
    /// key without the leading `contract:{addr}:` prefix, i.e. it's
    /// whatever the in-memory StateManager stored as the slot's key
    /// (e.g. `"slot:0"`). On rollback we re-assemble the full DB key
    /// as `format!("contract:{}:{}", addr, slot_key_suffix)`.
    pub slots: Vec<(String, String)>,
}

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
    /// Accounts destroyed in this block.
    ///
    /// The second tuple element is a JSON-serialized
    /// [`DestroyedAccountDetails`] carrying the account metadata,
    /// the pre-destroy code blob, and every pre-destroy storage slot,
    /// so that `rollback_block` can fully restore the contract. For
    /// backwards compatibility with pending undo records written
    /// before the richer format existed, the reader accepts the
    /// legacy form (a bare `"balance|nonce|code_hash"` string) and
    /// falls through to the old "restore account row only" path.
    pub destroyed_accounts: Vec<(String, String)>,
    /// Receipt root computed for this block
    pub receipt_root: Option<String>,
    /// State root computed for this block
    pub state_root: Option<String>,
}

/// Result of a [`PendingBatch::lookup`] query.
///
/// Used by SLOAD to implement read-your-writes within a single
/// execution frame: a SSTORE earlier in the same frame must be
/// visible to a later SLOAD on the same key, even though the write
/// hasn't been committed to RocksDB yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingLookup<'a> {
    /// The key has a buffered put — return this value instead of
    /// hitting disk. Equivalent to "the contract just wrote here".
    Buffered(&'a String),
    /// The key has a buffered delete — treat this as if disk returned
    /// the empty / default value. Equivalent to "the contract just
    /// deleted this slot".
    Tombstoned,
    /// The key is not in the pending buffer at all — fall through to
    /// the underlying ContractStorage / RocksDB read.
    NotBuffered,
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

    /// Look up `key` in the pending buffer.
    ///
    /// SLOAD must call this BEFORE reading from the underlying
    /// `ContractStorage`, so that an SSTORE earlier in the same frame
    /// is visible to a later SLOAD (read-your-writes). The previous
    /// implementation only ever read from disk, so a contract pattern
    /// like
    ///
    /// ```text
    ///     PUSH1 v   PUSH1 k   SSTORE   PUSH1 k   SLOAD
    /// ```
    ///
    /// returned `0` (the on-disk value) instead of `v`. That broke
    /// every standard accumulator / counter pattern within a single
    /// transaction.
    pub fn lookup(&self, key: &str) -> PendingLookup<'_> {
        match self.changes.get(key) {
            Some(Some(v)) => PendingLookup::Buffered(v),
            Some(None)    => PendingLookup::Tombstoned,
            None          => PendingLookup::NotBuffered,
        }
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

    /// Iterate the pending changes as `(&key, &Option<value>)` pairs.
    ///
    /// Used by [`ContractStorage::commit_batch`] to build a RocksDB
    /// `WriteBatch` WITHOUT consuming the buffer, so a write failure
    /// leaves the `PendingBatch` intact for the caller.
    fn iter(&self) -> impl Iterator<Item = (&String, &Option<String>)> {
        self.changes.iter()
    }

    /// Clear all pending changes after a successful commit.
    ///
    /// Separate from [`Self::discard`] only to keep the call sites
    /// self-documenting: `commit_batch` clears on success,
    /// REVERT/OutOfGas paths discard.
    fn clear(&mut self) {
        self.changes.clear();
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

    /// Direct get (non-strict).
    ///
    /// Returns `None` for genuine absence, and ALSO collapses
    /// read failures and UTF-8 corruption into `None` (logged via
    /// `slog_error!`). This is the "backwards-compatible" helper
    /// every existing SLOAD-ish path uses; if you need to tell
    /// "absent" apart from "corrupt" — e.g. audit tooling or a
    /// fail-closed SLOAD variant — use [`Self::get_state_strict`].
    ///
    /// The non-strict variant is preserved so existing callers don't
    /// suddenly start reporting errors on read failures that they
    /// historically treated as "value not set".
    pub fn get_state(&self, key: &str) -> Option<String> {
        let db_key = format!("contract:{}", key);
        match self.db.get(db_key.as_bytes()) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Some(s),
                Err(e) => {
                    slog_error!("runtime", "contract_state_utf8_corruption_may_be_false_negative",
                        key => key, error => &e.to_string(),
                        note => "returning None but the raw stored bytes are not valid UTF-8 — use get_state_strict to surface this");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                slog_error!("runtime", "contract_state_read_failed_may_be_false_negative",
                    key => key, error => &e.to_string(),
                    note => "returning None but the read failed — use get_state_strict to surface this");
                None
            }
        }
    }

    /// Strict variant of [`Self::get_state`] that distinguishes the
    /// three possible states:
    ///
    ///   - `Ok(None)`         → key is genuinely absent
    ///   - `Ok(Some(value))`  → key exists with a valid UTF-8 payload
    ///   - `Err(StorageError)` → read failed OR the stored bytes are
    ///     not valid UTF-8 (i.e. the on-disk record is corrupt)
    ///
    /// Use this from audit / explorer / reorg code that needs to tell
    /// a genuine miss apart from a disk corruption. The plain
    /// [`Self::get_state`] collapses the two into `None`, which is
    /// exactly the masking pattern that `load_undo_strict` /
    /// `has_undo_data_strict` close for block-level undo data. The
    /// main contract state read path was the one hole left in that
    /// family of strict variants.
    ///
    /// The SLOAD opcode currently still uses the non-strict variant
    /// for backward compatibility with existing tests; a follow-up
    /// can route it through this helper when the consensus semantics
    /// of "contract reads from a corrupted slot" are decided.
    pub fn get_state_strict(&self, key: &str) -> Result<Option<String>, StorageError> {
        let db_key = format!("contract:{}", key);
        match self.db.get(db_key.as_bytes()) {
            Ok(Some(data)) => match String::from_utf8(data.to_vec()) {
                Ok(s) => Ok(Some(s)),
                Err(e) => {
                    slog_error!("runtime", "contract_state_utf8_corruption_strict",
                        key => key, error => &e.to_string());
                    Err(StorageError::Serialization(format!(
                        "contract state for key '{}' is not valid UTF-8: {}",
                        key, e
                    )))
                }
            },
            Ok(None) => Ok(None),
            Err(e) => {
                slog_error!("runtime", "contract_state_read_failed_strict",
                    key => key, error => &e.to_string());
                Err(StorageError::ReadFailed(e.to_string()))
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
    /// If ANY write fails, NONE of the changes are persisted — that
    /// guarantee comes from RocksDB's `WriteBatch` itself.
    ///
    /// # Behaviour on failure (now preserved)
    ///
    /// On a successful write the `PendingBatch` is cleared so the
    /// caller can reuse it for the next frame. On a FAILED write the
    /// batch is left **untouched**: the caller's `&mut PendingBatch`
    /// still holds every pending change, so it can be re-logged,
    /// surfaced to audit tooling, or handed back to a retry path.
    ///
    /// The previous implementation called `batch.take_changes()`
    /// BEFORE the `db.write(wb)` call. `take_changes` uses
    /// `std::mem::take`, which replaces the inner map with a default
    /// (empty) — so after a failed commit the caller received an
    /// `Err` but the `PendingBatch` had already been emptied. A
    /// second commit attempt would then silently succeed on a
    /// no-longer-pending batch, erasing any record of what the VM
    /// was actually trying to persist. The doc comment only promised
    /// RocksDB-level atomicity, not "the batch in memory is also
    /// destroyed on any return path", so the silent clear was a
    /// surprising and hard-to-notice footgun.
    ///
    /// The new flow:
    ///
    ///   1. If the batch is empty → return `Ok(())` (no-op).
    ///   2. Build the `WriteBatch` by **borrowing** `batch.changes`.
    ///   3. Call `self.db.write(wb)`.
    ///      - On `Ok(())` → clear the batch and return `Ok(())`.
    ///      - On `Err(e)` → leave the batch intact and return the
    ///        error as `VmError::Other`.
    pub fn commit_batch(&self, batch: &mut PendingBatch) -> Result<(), VmError> {
        if batch.is_empty() {
            return Ok(());
        }

        // Borrow via PendingBatch::iter() — do NOT consume the buffer
        // — so a write failure leaves the PendingBatch intact for the
        // caller to inspect, log, or retry.
        let mut wb = WriteBatch::default();
        for (key, value) in batch.iter() {
            let db_key = format!("contract:{}", key);
            match value {
                Some(v) => wb.put(db_key.as_bytes(), v.as_bytes()),
                None    => wb.delete(db_key.as_bytes()),
            }
        }

        match self.db.write(wb) {
            Ok(()) => {
                // Write succeeded → drop the pending state so the
                // caller can reuse the batch for the next frame.
                batch.clear();
                Ok(())
            }
            Err(e) => {
                // Write failed → RocksDB guarantees no partial state
                // was persisted. Leave the batch as-is so the caller
                // still sees exactly what failed to land.
                slog_error!("runtime", "contract_commit_batch_write_failed_batch_preserved",
                    error => &e.to_string(),
                    pending_len => batch.len());
                Err(VmError::Other(format!("WriteBatch commit failed: {}", e)))
            }
        }
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

        // Restore destroyed accounts.
        //
        // For each destroyed contract we try to parse the second tuple
        // element as JSON-encoded `DestroyedAccountDetails`; if it
        // parses we restore the account metadata, the pre-destroy code
        // blob, and every pre-destroy storage slot, reversing the full
        // SELFDESTRUCT. If it does NOT parse (i.e. the record was
        // written before this patch, when `destroyed_accounts` only
        // ever held a bare `"balance|nonce|code_hash"` string), we
        // fall back to the legacy behaviour of restoring the account
        // row alone — that's all the old format could recover.
        for (addr, payload) in &undo.destroyed_accounts {
            match serde_json::from_str::<DestroyedAccountDetails>(payload) {
                Ok(details) => {
                    // v2 path — restore account, code, and all slots.
                    let account_key = format!("contract:account:{}", addr);
                    batch.put(account_key.as_bytes(), details.meta.as_bytes());

                    if let Some(code_hex) = details.code {
                        let code_key = format!("contract:code:{}", addr);
                        batch.put(code_key.as_bytes(), code_hex.as_bytes());
                    }

                    for (slot_key_suffix, old_value) in details.slots {
                        // Slot keys are stored by `persist_with_undo` as
                        // `{addr}:{suffix}` → DB key `contract:{addr}:{suffix}`.
                        let slot_db_key =
                            format!("contract:{}:{}", addr, slot_key_suffix);
                        batch.put(slot_db_key.as_bytes(), old_value.as_bytes());
                    }
                }
                Err(_) => {
                    // Legacy format fallback — the payload is raw
                    // account metadata (`"balance|nonce|code_hash"`),
                    // not JSON. Restore only the account row so that
                    // pending undo records written before this patch
                    // still roll back cleanly. Code + storage will be
                    // missing, which matches the old (buggy) behaviour;
                    // by definition no post-patch block can hit this
                    // branch.
                    let db_key = format!("contract:account:{}", addr);
                    batch.put(db_key.as_bytes(), payload.as_bytes());
                }
            }
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

    // ─── commit_batch preservation tests ─────────────────────────────

    #[test]
    fn commit_batch_empty_is_noop() {
        let s = tmp_storage();
        let mut batch = PendingBatch::new();
        assert!(batch.is_empty());
        s.commit_batch(&mut batch).unwrap();
        assert!(batch.is_empty());
    }

    #[test]
    fn commit_batch_clears_on_successful_write() {
        let s = tmp_storage();
        let mut batch = PendingBatch::new();
        batch.put("alpha".into(), "v1".into());
        batch.put("beta".into(),  "v2".into());
        batch.delete("gamma".into());
        assert_eq!(batch.len(), 3);

        // Successful commit → batch is cleared AND the values are on disk.
        s.commit_batch(&mut batch).unwrap();
        assert!(batch.is_empty(), "successful commit must clear the pending batch");

        assert_eq!(s.get_state("alpha"), Some("v1".into()));
        assert_eq!(s.get_state("beta"),  Some("v2".into()));
        assert_eq!(s.get_state("gamma"), None); // the delete landed as "no key"
    }

    #[test]
    fn commit_batch_idempotent_on_same_buffer() {
        // Regression for the "take_changes happens before the write"
        // bug. The old flow would, on a SECOND commit of the same
        // in-memory batch, silently succeed on an empty buffer even
        // though the caller re-staged writes in between. With the new
        // flow, a second commit of the SAME buffer that has been
        // re-populated with new writes after the first commit must
        // succeed and land the new writes — and must NOT leak the
        // previously-committed keys.
        let s = tmp_storage();
        let mut batch = PendingBatch::new();
        batch.put("round1".into(), "first".into());
        s.commit_batch(&mut batch).unwrap();
        assert!(batch.is_empty());
        assert_eq!(s.get_state("round1"), Some("first".into()));

        // Re-stage on the same buffer and commit again.
        batch.put("round2".into(), "second".into());
        s.commit_batch(&mut batch).unwrap();
        assert!(batch.is_empty());
        assert_eq!(s.get_state("round1"), Some("first".into()));
        assert_eq!(s.get_state("round2"), Some("second".into()));
    }

    #[test]
    fn commit_batch_can_still_observe_buffer_contents_before_commit() {
        // The previous `take_changes()` flow moved the internal map
        // out of the PendingBatch BEFORE calling db.write(), so even
        // a successful commit would, at the moment of dispatch, have
        // a partially-empty batch depending on how the caller
        // observed it. The new flow borrows during the write, so the
        // buffer is visible up until the write succeeds.
        let s = tmp_storage();
        let mut batch = PendingBatch::new();
        batch.put("x".into(), "1".into());
        assert_eq!(batch.len(), 1);
        assert!(matches!(batch.lookup("x"), PendingLookup::Buffered(_)));
        s.commit_batch(&mut batch).unwrap();
        assert_eq!(batch.len(), 0);
        assert!(matches!(batch.lookup("x"), PendingLookup::NotBuffered));
    }

    // ─── get_state_strict tests ──────────────────────────────────────

    #[test]
    fn get_state_strict_returns_none_for_absent_key() {
        let s = tmp_storage();
        assert!(matches!(s.get_state_strict("never_written"), Ok(None)));
    }

    #[test]
    fn get_state_strict_returns_value_for_valid_utf8_key() {
        let s = tmp_storage();
        s.set_state("hello", "world").unwrap();
        let v = s.get_state_strict("hello").unwrap();
        assert_eq!(v, Some("world".to_string()));
        // Non-strict agrees on the happy path.
        assert_eq!(s.get_state("hello"), Some("world".to_string()));
    }

    #[test]
    fn get_state_strict_surfaces_utf8_corruption_as_err() {
        // Regression for the main-state UTF-8 masking bug. The
        // non-strict `get_state` collapses UTF-8 corruption into
        // `None` (logged but otherwise silent); the strict variant
        // must return Err so audit / reorg code can tell a genuine
        // miss apart from a damaged on-disk record.
        let s = tmp_storage();

        // Plant raw non-UTF-8 bytes under the correctly-namespaced
        // contract: key directly via the underlying DB handle — the
        // same technique the undo tests use.
        let bad: [u8; 4] = [0xff, 0xfe, 0xfd, 0xfc]; // not valid UTF-8
        s.db.put(b"contract:bad_key", bad).expect("raw put");

        // Non-strict masks corruption as None (with log).
        assert_eq!(s.get_state("bad_key"), None,
            "non-strict get_state must return None on UTF-8 corruption for backward compat");

        // Strict variant surfaces it as an explicit error.
        let strict = s.get_state_strict("bad_key");
        assert!(strict.is_err(),
            "get_state_strict must return Err on UTF-8 corruption, got {:?}", strict);
        let msg = format!("{}", strict.unwrap_err());
        assert!(
            msg.contains("not valid UTF-8") || msg.contains("Serialization"),
            "expected corruption error mentioning UTF-8, got: {}",
            msg
        );
    }
}
