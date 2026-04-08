// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::StorageError;
use crate::runtime::vm::contracts::contract_storage::ContractStorage;
use crate::slog_error;

pub struct VMContext {
    storage: ContractStorage,
}

impl VMContext {
    pub fn new(storage: ContractStorage) -> Self {
        Self { storage }
    }

    /// Write a key-value pair to storage.
    ///
    /// Returns `Result<(), StorageError>` so callers can handle failures.
    /// On error, logs the failure before propagating.
    pub fn set(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.storage.set_state(key, value).inspect_err(|e| {
            slog_error!("runtime", "vm_context_set_failed", key => key, error => &e.to_string());
        })
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.storage.get_state(key)
    }

    /// Delete a key from storage.
    ///
    /// Returns `Result<(), StorageError>` so callers can handle failures.
    /// On error, logs the failure before propagating.
    pub fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.storage.delete_state(key).inspect_err(|e| {
            slog_error!("runtime", "vm_context_delete_failed", key => key, error => &e.to_string());
        })
    }

    /// Write with full error propagation.
    /// DEPRECATED: use `set()` directly, which now returns Result.
    #[deprecated(note = "use set() directly, which now returns Result")]
    pub fn set_checked(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.set(key, value)
    }

    /// Delete with full error propagation.
    /// DEPRECATED: use `delete()` directly, which now returns Result.
    #[deprecated(note = "use delete() directly, which now returns Result")]
    pub fn delete_checked(&self, key: &str) -> Result<(), StorageError> {
        self.delete(key)
    }

    /// Get the DB path for creating sub-contexts
    pub fn db_path(&self) -> &str {
        self.storage.path()
    }

    /// Get a reference to the underlying storage (for atomic WriteBatch commits)
    pub fn storage(&self) -> &ContractStorage {
        &self.storage
    }
}
