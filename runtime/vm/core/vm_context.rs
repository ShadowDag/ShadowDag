// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::runtime::vm::contracts::contract_storage::ContractStorage;

pub struct VMContext {
    storage: ContractStorage,
}

impl VMContext {
    pub fn new(storage: ContractStorage) -> Self {
        Self { storage }
    }

    pub fn set(&self, key: &str, value: &str) {
        self.storage.set_state(key, value);
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.storage.get_state(key)
    }

    pub fn delete(&self, key: &str) {
        self.storage.delete_state(key);
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
