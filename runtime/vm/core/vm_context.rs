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

    /// Write a key-value pair. Logs and ignores errors at this layer so that
    /// callers (Executor, VM) that previously assumed infallible writes continue
    /// to compile. The underlying `ContractStorage::set_state` now returns
    /// `Result<(), StorageError>` for callers that need the error.
    pub fn set(&self, key: &str, value: &str) {
        if let Err(e) = self.storage.set_state(key, value) {
            slog_error!("runtime", "vm_context_set_failed", key => key, error => &e.to_string());
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.storage.get_state(key)
    }

    /// Delete a key. Logs and ignores errors at this layer (see `set` rationale).
    pub fn delete(&self, key: &str) {
        if let Err(e) = self.storage.delete_state(key) {
            slog_error!("runtime", "vm_context_delete_failed", key => key, error => &e.to_string());
        }
    }

    /// Write with full error propagation for callers that need it.
    pub fn set_checked(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.storage.set_state(key, value)
    }

    /// Delete with full error propagation for callers that need it.
    pub fn delete_checked(&self, key: &str) -> Result<(), StorageError> {
        self.storage.delete_state(key)
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
