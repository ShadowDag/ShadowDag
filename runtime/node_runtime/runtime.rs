// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::errors::StorageError;
use crate::runtime::node_runtime::runtime_manager::RuntimeManager;

pub struct Runtime {
    manager: RuntimeManager,
}

impl Runtime {
    pub fn new(manager: RuntimeManager) -> Self {
        Self { manager }
    }

    /// Persist a (key, value) pair into the runtime DB.
    ///
    /// Returns `Err(StorageError::WriteFailed)` if the underlying
    /// `RuntimeManager::set_state` write fails. The previous wrapper
    /// returned `()` and silently swallowed the error reported by
    /// the manager — same masking pattern the manager itself just
    /// closed in this commit.
    pub fn set_value(&self, key: &str, value: &str) -> Result<(), StorageError> {
        self.manager.set_state(key, value)
    }

    /// Read a (key, value) pair from the runtime DB.
    ///
    /// Non-strict: collapses "absent / read-failed / non-UTF-8" into
    /// `None` (with logging in the manager). Use
    /// [`Self::get_value_strict`] when the caller needs to tell the
    /// three apart.
    pub fn get_value(&self, key: &str) -> Option<String> {
        self.manager.get_state(key)
    }

    /// Read a (key, value) pair from the runtime DB — strict variant.
    ///
    /// See `RuntimeManager::get_state_strict` for the contract:
    /// `Ok(None)` for genuine absence, `Ok(Some(_))` for a valid
    /// UTF-8 value, `Err(_)` for read failure or UTF-8 corruption.
    pub fn get_value_strict(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.manager.get_state_strict(key)
    }
}
