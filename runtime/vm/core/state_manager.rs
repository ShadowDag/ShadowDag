// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// State Manager — global state transition engine for smart contracts.
//
// Manages:
//   - Account state (balance, nonce, code hash, storage root)
//   - State transitions (atomic, reversible)
//   - State snapshots for nested calls (journal-based)
//   - Merkle state root computation
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::BTreeMap;
use sha2::{Sha256, Digest};
use crate::errors::VmError;

/// An account in the state
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub address: String,
    pub balance: u64,
    pub nonce: u64,
    pub code_hash: String,
    pub storage_root: String,
    pub code: Vec<u8>,
}

impl Account {
    /// Create an externally owned account (no code)
    pub fn new_eoa(address: String, balance: u64) -> Self {
        Self {
            address,
            balance,
            nonce: 0,
            code_hash: "0".repeat(64),
            storage_root: "0".repeat(64),
            code: Vec::new(),
        }
    }

    /// Create a contract account
    pub fn new_contract(address: String, code: Vec<u8>) -> Self {
        let code_hash = {
            let mut h = <Sha256 as Digest>::new();
            Digest::update(&mut h, &code);
            hex::encode(Digest::finalize(h))
        };
        Self {
            address,
            balance: 0,
            nonce: 1, // Contracts start at nonce 1
            code_hash,
            storage_root: "0".repeat(64),
            code,
        }
    }

    pub fn is_contract(&self) -> bool {
        !self.code.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.balance == 0 && self.nonce == 0 && self.code.is_empty()
    }
}

/// Journal entry for state changes (enables rollback)
#[derive(Debug, Clone)]
pub enum StateChange {
    /// Account balance changed
    BalanceChange { address: String, old_balance: u64, new_balance: u64 },
    /// Account nonce incremented
    NonceChange { address: String, old_nonce: u64, new_nonce: u64 },
    /// Account created
    AccountCreated { address: String },
    /// Account destroyed (SELFDESTRUCT)
    AccountDestroyed { address: String, account: Account },
    /// Storage value changed
    StorageChange { address: String, key: String, old_value: Option<String>, new_value: Option<String> },
    /// Contract code changed
    CodeChanged { address: String, old_code_hash: String, old_code: Vec<u8> },
}

/// State snapshot ID
type SnapshotId = usize;

/// Global state manager with journal-based rollback
pub struct StateManager {
    /// Current account state
    accounts: BTreeMap<String, Account>,
    /// Storage: address -> key -> value
    storage: BTreeMap<String, BTreeMap<String, String>>,
    /// Journal of changes for rollback
    journal: Vec<StateChange>,
    /// Snapshot stack (journal length at snapshot time)
    snapshots: Vec<usize>,
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            accounts: BTreeMap::new(),
            storage: BTreeMap::new(),
            journal: Vec::with_capacity(256),
            snapshots: Vec::with_capacity(16),
        }
    }

    // ─── Account Operations ──────────────────────────────────────────

    /// Get account (creates empty if not exists)
    pub fn get_account(&self, address: &str) -> Option<&Account> {
        self.accounts.get(address)
    }

    /// Get or create account
    pub fn get_or_create_account(&mut self, address: &str) -> &Account {
        if !self.accounts.contains_key(address) {
            let acc = Account::new_eoa(address.to_string(), 0);
            self.journal.push(StateChange::AccountCreated { address: address.to_string() });
            self.accounts.insert(address.to_string(), acc);
        }
        self.accounts.entry(address.to_string()).or_insert_with(|| Account::new_eoa(address.to_string(), 0))
    }

    /// Get balance
    pub fn get_balance(&self, address: &str) -> u64 {
        self.accounts.get(address).map(|a| a.balance).unwrap_or(0)
    }

    /// Transfer value between accounts
    pub fn transfer(&mut self, from: &str, to: &str, value: u64) -> Result<(), VmError> {
        let from_balance = self.get_balance(from);
        if from_balance < value {
            return Err(VmError::ContractError(format!(
                "insufficient balance: {} has {} but needs {}",
                from, from_balance, value
            )));
        }

        // Debit sender
        self.set_balance(from, from_balance - value)?;
        // Credit receiver
        let to_balance = self.get_balance(to);
        self.set_balance(to, to_balance.saturating_add(value))?;

        Ok(())
    }

    /// Set account balance (with journal entry)
    pub fn set_balance(&mut self, address: &str, new_balance: u64) -> Result<(), VmError> {
        self.get_or_create_account(address);
        let account = self.accounts.get_mut(address)
            .ok_or_else(|| VmError::Other(format!(
                "account missing after get_or_create for {}", address
            )))?;
        let old_balance = account.balance;
        account.balance = new_balance;
        self.journal.push(StateChange::BalanceChange {
            address: address.to_string(), old_balance, new_balance
        });
        Ok(())
    }

    /// Increment nonce
    pub fn increment_nonce(&mut self, address: &str) -> Result<u64, VmError> {
        self.get_or_create_account(address);
        let account = self.accounts.get_mut(address)
            .ok_or_else(|| VmError::Other(format!(
                "account missing after get_or_create for {}", address
            )))?;
        let old_nonce = account.nonce;
        account.nonce = old_nonce.saturating_add(1);
        let new_nonce = account.nonce;
        self.journal.push(StateChange::NonceChange {
            address: address.to_string(), old_nonce, new_nonce
        });
        Ok(new_nonce)
    }

    /// Get nonce
    pub fn get_nonce(&self, address: &str) -> u64 {
        self.accounts.get(address).map(|a| a.nonce).unwrap_or(0)
    }

    /// Deploy contract code to an address
    pub fn set_code(&mut self, address: &str, code: Vec<u8>) -> Result<(), VmError> {
        self.get_or_create_account(address);
        let account = self.accounts.get_mut(address)
            .ok_or_else(|| VmError::Other(format!(
                "account missing after get_or_create for {}", address
            )))?;

        // Record old state for rollback
        let old_code_hash = account.code_hash.clone();
        let old_code = std::mem::take(&mut account.code);

        // Apply new code
        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, &code);
        account.code_hash = hex::encode(Digest::finalize(h));
        account.code = code;
        if account.nonce == 0 {
            account.nonce = 1; // Contracts start at nonce 1
        }

        // Journal entry for rollback
        self.journal.push(StateChange::CodeChanged {
            address: address.to_string(),
            old_code_hash,
            old_code,
        });

        Ok(())
    }

    /// Get contract code
    pub fn get_code(&self, address: &str) -> Vec<u8> {
        self.accounts.get(address)
            .map(|a| a.code.clone())
            .unwrap_or_default()
    }

    /// Destroy a contract account (SELFDESTRUCT).
    /// Records the full account state in the journal for rollback.
    pub fn destroy_account(&mut self, address: &str) -> Result<(), VmError> {
        if let Some(account) = self.accounts.remove(address) {
            self.journal.push(StateChange::AccountDestroyed {
                address: address.to_string(),
                account,
            });
            // Also clear storage
            self.storage.remove(address);
            Ok(())
        } else {
            Err(VmError::Other(format!("cannot destroy non-existent account: {}", address)))
        }
    }

    // ─── Storage Operations ──────────────────────────────────────────

    /// Read from contract storage
    pub fn storage_load(&self, address: &str, key: &str) -> Option<String> {
        self.storage.get(address)
            .and_then(|m| m.get(key))
            .cloned()
    }

    /// Write to contract storage (with journal entry)
    pub fn storage_store(&mut self, address: &str, key: &str, value: &str) {
        let old_value = self.storage_load(address, key);

        self.journal.push(StateChange::StorageChange {
            address: address.to_string(),
            key: key.to_string(),
            old_value: old_value.clone(),
            new_value: Some(value.to_string()),
        });

        self.storage
            .entry(address.to_string())
            .or_default()
            .insert(key.to_string(), value.to_string());
    }

    /// Delete from contract storage
    pub fn storage_delete(&mut self, address: &str, key: &str) {
        let old_value = self.storage_load(address, key);

        self.journal.push(StateChange::StorageChange {
            address: address.to_string(),
            key: key.to_string(),
            old_value,
            new_value: None,
        });

        if let Some(m) = self.storage.get_mut(address) {
            m.remove(key);
        }
    }

    // ─── Snapshot & Rollback ─────────────────────────────────────────

    /// Take a snapshot (returns snapshot ID)
    pub fn snapshot(&mut self) -> SnapshotId {
        let id = self.snapshots.len();
        self.snapshots.push(self.journal.len());
        id
    }

    /// Rollback to a snapshot (undoes all changes since snapshot)
    pub fn rollback(&mut self, snapshot_id: SnapshotId) -> Result<(), VmError> {
        let journal_pos = self.snapshots.get(snapshot_id)
            .copied()
            .ok_or(VmError::Other(format!("invalid snapshot ID: {}", snapshot_id)))?;

        // Replay journal entries in reverse to undo changes
        while self.journal.len() > journal_pos {
            if let Some(change) = self.journal.pop() {
                self.undo_change(change);
            }
        }

        // Remove all snapshots after this one
        self.snapshots.truncate(snapshot_id);

        Ok(())
    }

    /// Commit a snapshot (discard the rollback point)
    pub fn commit(&mut self, snapshot_id: SnapshotId) -> Result<(), VmError> {
        if snapshot_id >= self.snapshots.len() {
            return Err(VmError::Other(format!(
                "commit: invalid snapshot_id {} (only {} snapshots exist)",
                snapshot_id, self.snapshots.len()
            )));
        }
        self.snapshots.truncate(snapshot_id);
        Ok(())
    }

    /// Undo a single state change
    fn undo_change(&mut self, change: StateChange) {
        match change {
            StateChange::BalanceChange { address, old_balance, .. } => {
                if let Some(acc) = self.accounts.get_mut(&address) {
                    acc.balance = old_balance;
                }
            }
            StateChange::NonceChange { address, old_nonce, .. } => {
                if let Some(acc) = self.accounts.get_mut(&address) {
                    acc.nonce = old_nonce;
                }
            }
            StateChange::AccountCreated { address } => {
                self.accounts.remove(&address);
                self.storage.remove(&address);
            }
            StateChange::AccountDestroyed { address, account } => {
                self.accounts.insert(address, account);
            }
            StateChange::StorageChange { address, key, old_value, .. } => {
                match old_value {
                    Some(v) => {
                        self.storage
                            .entry(address)
                            .or_default()
                            .insert(key, v);
                    }
                    None => {
                        if let Some(m) = self.storage.get_mut(&address) {
                            m.remove(&key);
                        }
                    }
                }
            }
            StateChange::CodeChanged { address, old_code_hash, old_code } => {
                if let Some(acc) = self.accounts.get_mut(&address) {
                    acc.code_hash = old_code_hash;
                    acc.code = old_code;
                }
            }
        }
    }

    // ─── State Root ──────────────────────────────────────────────────

    /// Compute state root hash (deterministic Merkle root of all accounts)
    pub fn state_root(&self) -> String {
        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, b"ShadowDAG_StateRoot_v2"); // v2 includes storage

        for (address, account) in &self.accounts {
            Digest::update(&mut h, address.as_bytes());
            Digest::update(&mut h, account.balance.to_le_bytes());
            Digest::update(&mut h, account.nonce.to_le_bytes());
            Digest::update(&mut h, account.code_hash.as_bytes());
            // Include storage hash — different storage = different root
            let storage_hash = self.compute_storage_hash(address);
            Digest::update(&mut h, storage_hash.as_bytes());
        }

        hex::encode(Digest::finalize(h))
    }

    /// Compute a deterministic hash of an account's storage entries.
    fn compute_storage_hash(&self, address: &str) -> String {
        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, b"storage:");
        if let Some(storage) = self.storage.get(address) {
            // Sort keys for deterministic ordering (BTreeMap is already sorted)
            for (key, value) in storage.iter() {
                Digest::update(&mut h, key.as_bytes());
                Digest::update(&mut h, value.as_bytes());
            }
        }
        hex::encode(Digest::finalize(h))
    }

    /// Number of accounts
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_transfer() {
        let mut sm = StateManager::new();
        sm.set_balance("alice", 1000).unwrap();
        sm.set_balance("bob", 0).unwrap();

        sm.transfer("alice", "bob", 300).unwrap();

        assert_eq!(sm.get_balance("alice"), 700);
        assert_eq!(sm.get_balance("bob"), 300);
    }

    #[test]
    fn insufficient_balance_rejected() {
        let mut sm = StateManager::new();
        sm.set_balance("alice", 100).unwrap();
        assert!(sm.transfer("alice", "bob", 200).is_err());
    }

    #[test]
    fn snapshot_and_rollback() {
        let mut sm = StateManager::new();
        sm.set_balance("alice", 1000).unwrap();

        let snap = sm.snapshot();
        sm.transfer("alice", "bob", 500).unwrap();
        assert_eq!(sm.get_balance("alice"), 500);

        sm.rollback(snap).unwrap();
        assert_eq!(sm.get_balance("alice"), 1000);
        assert_eq!(sm.get_balance("bob"), 0);
    }

    #[test]
    fn nested_snapshots() {
        let mut sm = StateManager::new();
        sm.set_balance("a", 1000).unwrap();

        let s1 = sm.snapshot();
        sm.transfer("a", "b", 300).unwrap();

        let s2 = sm.snapshot();
        sm.transfer("a", "c", 200).unwrap();

        // Rollback inner
        sm.rollback(s2).unwrap();
        assert_eq!(sm.get_balance("a"), 700);
        assert_eq!(sm.get_balance("c"), 0);

        // Rollback outer
        sm.rollback(s1).unwrap();
        assert_eq!(sm.get_balance("a"), 1000);
    }

    #[test]
    fn storage_ops() {
        let mut sm = StateManager::new();
        sm.storage_store("contract_a", "key1", "value1");
        assert_eq!(sm.storage_load("contract_a", "key1"), Some("value1".to_string()));

        sm.storage_delete("contract_a", "key1");
        assert_eq!(sm.storage_load("contract_a", "key1"), None);
    }

    #[test]
    fn storage_rollback() {
        let mut sm = StateManager::new();
        sm.storage_store("c", "k", "old");

        let snap = sm.snapshot();
        sm.storage_store("c", "k", "new");
        assert_eq!(sm.storage_load("c", "k"), Some("new".to_string()));

        sm.rollback(snap).unwrap();
        assert_eq!(sm.storage_load("c", "k"), Some("old".to_string()));
    }

    #[test]
    fn nonce_increment() {
        let mut sm = StateManager::new();
        assert_eq!(sm.get_nonce("alice"), 0);
        assert_eq!(sm.increment_nonce("alice").unwrap(), 1);
        assert_eq!(sm.get_nonce("alice"), 1);
        assert_eq!(sm.increment_nonce("alice").unwrap(), 2);
        assert_eq!(sm.get_nonce("alice"), 2);
    }

    #[test]
    fn state_root_deterministic() {
        let mut sm1 = StateManager::new();
        sm1.set_balance("a", 100).unwrap();
        sm1.set_balance("b", 200).unwrap();

        let mut sm2 = StateManager::new();
        sm2.set_balance("a", 100).unwrap();
        sm2.set_balance("b", 200).unwrap();

        assert_eq!(sm1.state_root(), sm2.state_root());
    }

    #[test]
    fn contract_deployment() {
        let mut sm = StateManager::new();
        let code = vec![0x60, 0x00, 0x60, 0x00, 0x52];
        sm.set_code("contract_1", code.clone()).unwrap();

        let acc = sm.get_account("contract_1").unwrap();
        assert!(acc.is_contract());
        assert_eq!(acc.code, code);
        assert!(acc.nonce >= 1);
    }
}
