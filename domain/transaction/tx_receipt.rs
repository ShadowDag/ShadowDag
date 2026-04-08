// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Transaction Receipt — Tracks the lifecycle and status of transactions
// from submission to final confirmation.
//
// Status flow: Pending → InMempool → InBlock → Confirmed → Final
//                                ↘ Rejected / Expired
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::runtime::vm::core::vm::ExecutionResult;

/// Transaction lifecycle status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TxStatus {
    /// Transaction submitted but not yet in mempool
    Pending,
    /// Transaction accepted into mempool
    InMempool,
    /// Transaction included in a block (with block hash)
    InBlock { block_hash: String, block_height: u64 },
    /// Transaction has N confirmations
    Confirmed { block_hash: String, block_height: u64, confirmations: u64 },
    /// Transaction reached finality (irreversible)
    Final { block_hash: String, block_height: u64, confirmations: u64 },
    /// Transaction rejected (with reason)
    Rejected { reason: String },
    /// Transaction expired from mempool
    Expired,
    /// Transaction replaced by higher-fee transaction
    Replaced { replacement_hash: String },
}

impl TxStatus {
    pub fn is_confirmed(&self) -> bool {
        matches!(self, TxStatus::Confirmed { .. } | TxStatus::Final { .. })
    }
    pub fn is_final(&self) -> bool {
        matches!(self, TxStatus::Final { .. })
    }
    pub fn is_failed(&self) -> bool {
        matches!(self, TxStatus::Rejected { .. } | TxStatus::Expired | TxStatus::Replaced { .. })
    }
}

/// Full transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxReceipt {
    /// Transaction hash
    pub tx_hash:        String,
    /// Current status
    pub status:         TxStatus,
    /// Fee paid
    pub fee:            u64,
    /// Gas used (for contract transactions)
    pub gas_used:       u64,
    /// Contract address (if contract creation)
    pub contract_addr:  Option<String>,
    /// Log entries from contract execution
    pub logs:           Vec<ReceiptLog>,
    /// When the transaction was first seen
    pub submitted_at:   u64,
    /// When the status was last updated
    pub updated_at:     u64,
    /// Number of outputs
    pub output_count:   usize,
    /// Total output value
    pub total_value:    u64,
    /// Whether execution succeeded (true) or reverted/failed (false)
    pub execution_success: bool,
    /// Return data from contract execution (hex-encoded)
    pub return_data: Option<String>,
    /// Revert reason if execution failed
    pub revert_reason: Option<String>,
    /// VM version used for execution
    pub vm_version: u8,
    /// Block-level transaction index
    pub tx_index: Option<u32>,
    /// Block height where this TX was included
    pub block_height: Option<u64>,
}

/// Log entry in a receipt (from contract execution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptLog {
    pub contract:  String,
    pub topics:    Vec<String>,    // 0-4 indexed topics
    pub data:      String,         // Non-indexed data (hex)
    pub log_index: usize,
}

impl TxReceipt {
    pub fn new_pending(tx_hash: String, fee: u64, output_count: usize, total_value: u64) -> Self {
        let now = now_secs();
        Self {
            tx_hash,
            status:        TxStatus::Pending,
            fee,
            gas_used:      0,
            contract_addr: None,
            logs:          vec![],
            submitted_at:  now,
            updated_at:    now,
            output_count,
            total_value,
            execution_success: false,
            return_data:       None,
            revert_reason:     None,
            vm_version:        0,
            tx_index:          None,
            block_height:      None,
        }
    }

    /// Construct a receipt from a contract execution result.
    pub fn from_execution(
        tx_hash: &str,
        outcome: &ExecutionResult,
        block_hash: &str,
        block_height: u64,
        tx_index: u32,
    ) -> Self {
        let now = now_secs();
        let (execution_success, gas_used, logs, return_data, revert_reason) = match outcome {
            ExecutionResult::Success { gas_used, return_data, logs } => {
                let receipt_logs: Vec<ReceiptLog> = logs.iter().enumerate().map(|(i, log)| {
                    ReceiptLog {
                        contract: log.contract.clone(),
                        topics: log.topics.iter().map(|t| {
                            let h = t.to_hex();
                            // Pad to 64 hex chars (32 bytes)
                            format!("{:0>64}", h)
                        }).collect(),
                        data: hex::encode(&log.data),
                        log_index: i,
                    }
                }).collect();
                (true, *gas_used, receipt_logs, Some(hex::encode(return_data)), None)
            }
            ExecutionResult::Revert { gas_used, reason } => {
                (false, *gas_used, vec![], None, Some(reason.clone()))
            }
            ExecutionResult::OutOfGas { gas_used } => {
                (false, *gas_used, vec![], None, Some("out of gas".to_string()))
            }
            ExecutionResult::Error { gas_used, message } => {
                (false, *gas_used, vec![], None, Some(message.clone()))
            }
        };

        Self {
            tx_hash: tx_hash.to_string(),
            status: TxStatus::InBlock {
                block_hash: block_hash.to_string(),
                block_height,
            },
            fee: 0,
            gas_used,
            contract_addr: None,
            logs,
            submitted_at: now,
            updated_at: now,
            output_count: 0,
            total_value: 0,
            execution_success,
            return_data,
            revert_reason,
            vm_version: 1,
            tx_index: Some(tx_index),
            block_height: Some(block_height),
        }
    }

    pub fn update_status(&mut self, status: TxStatus) {
        self.status = status;
        self.updated_at = now_secs();
    }

    pub fn set_in_block(&mut self, block_hash: &str, block_height: u64) {
        self.status = TxStatus::InBlock {
            block_hash: block_hash.to_string(),
            block_height,
        };
        self.updated_at = now_secs();
    }

    pub fn set_confirmed(&mut self, block_hash: &str, block_height: u64, confirmations: u64) {
        if confirmations >= 100 {
            self.status = TxStatus::Final { block_hash: block_hash.to_string(), block_height, confirmations };
        } else {
            self.status = TxStatus::Confirmed { block_hash: block_hash.to_string(), block_height, confirmations };
        }
        self.updated_at = now_secs();
    }

    /// Time since submission in seconds
    pub fn age_secs(&self) -> u64 {
        now_secs().saturating_sub(self.submitted_at)
    }

    /// Confirmation time (if confirmed)
    pub fn confirmation_time_secs(&self) -> Option<u64> {
        if self.status.is_confirmed() {
            Some(self.updated_at.saturating_sub(self.submitted_at))
        } else {
            None
        }
    }
}

/// Transaction Receipt Store — tracks all known transaction receipts
pub struct ReceiptStore {
    receipts: RwLock<HashMap<String, TxReceipt>>,
    max_size: usize,
}

impl ReceiptStore {
    pub fn new(max_size: usize) -> Self {
        Self {
            receipts: RwLock::new(HashMap::with_capacity(max_size / 4)),
            max_size,
        }
    }

    /// Track a new transaction
    pub fn track(&self, receipt: TxReceipt) {
        let mut receipts = self.receipts.write().unwrap_or_else(|e| e.into_inner());

        // Evict old entries if at capacity
        if receipts.len() >= self.max_size {
            self.evict_old(&mut receipts);
        }

        // Still full after eviction — reject new receipt
        if receipts.len() >= self.max_size {
            return;
        }

        receipts.insert(receipt.tx_hash.clone(), receipt);
    }

    /// Get receipt for a transaction
    pub fn get(&self, tx_hash: &str) -> Option<TxReceipt> {
        self.receipts.read().unwrap_or_else(|e| e.into_inner()).get(tx_hash).cloned()
    }

    /// Update status of a transaction
    pub fn update_status(&self, tx_hash: &str, status: TxStatus) -> bool {
        let mut receipts = self.receipts.write().unwrap_or_else(|e| e.into_inner());
        if let Some(receipt) = receipts.get_mut(tx_hash) {
            receipt.update_status(status);
            true
        } else {
            false
        }
    }

    /// Mark a transaction as included in a block
    pub fn mark_in_block(&self, tx_hash: &str, block_hash: &str, height: u64) -> bool {
        let mut receipts = self.receipts.write().unwrap_or_else(|e| e.into_inner());
        if let Some(receipt) = receipts.get_mut(tx_hash) {
            receipt.set_in_block(block_hash, height);
            true
        } else {
            false
        }
    }

    /// Update confirmations for all in-block transactions
    pub fn update_confirmations(&self, current_height: u64) {
        let mut receipts = self.receipts.write().unwrap_or_else(|e| e.into_inner());
        for receipt in receipts.values_mut() {
            let (bh, bht) = match &receipt.status {
                TxStatus::InBlock { block_hash, block_height } => {
                    (block_hash.clone(), *block_height)
                }
                TxStatus::Confirmed { block_hash, block_height, .. } => {
                    (block_hash.clone(), *block_height)
                }
                _ => continue,
            };
            let confs = current_height.saturating_sub(bht);
            // Only transition to Confirmed when there is at least 1 confirmation.
            // 0 confirmations means the block is at the current height — stay at InBlock.
            if confs > 0 {
                receipt.set_confirmed(&bh, bht, confs);
            }
        }
    }

    /// Get all pending transactions
    pub fn pending(&self) -> Vec<TxReceipt> {
        self.receipts.read().unwrap_or_else(|e| e.into_inner()).values()
            .filter(|r| matches!(r.status, TxStatus::Pending | TxStatus::InMempool))
            .cloned()
            .collect()
    }

    pub fn count(&self) -> usize { self.receipts.read().unwrap_or_else(|e| e.into_inner()).len() }

    fn evict_old(&self, receipts: &mut HashMap<String, TxReceipt>) {
        // Remove final/rejected/expired receipts that are oldest
        let mut candidates: Vec<(String, u64)> = receipts.iter()
            .filter(|(_, r)| r.status.is_final() || r.status.is_failed())
            .map(|(h, r)| (h.clone(), r.updated_at))
            .collect();
        candidates.sort_by_key(|(_, t)| *t);

        let to_remove = candidates.len().min(self.max_size / 10);
        for (hash, _) in candidates.into_iter().take(to_remove) {
            receipts.remove(&hash);
        }
    }
}

/// Compute a deterministic receipt root from a list of receipts.
/// SHA-256 of concatenated (tx_hash | execution_success_byte | gas_used_le_bytes) for each receipt.
pub fn compute_receipt_root(receipts: &[TxReceipt]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    for r in receipts {
        hasher.update(r.tx_hash.as_bytes());
        hasher.update([if r.execution_success { 1u8 } else { 0u8 }]);
        hasher.update(r.gas_used.to_le_bytes());
    }
    hex::encode(hasher.finalize())
}

// ═══════════════════════════════════════════════════════════════════════════
// PERSISTENT RECEIPT STORAGE — DB-backed receipt persistence
// ═══════════════════════════════════════════════════════════════════════════

/// Save a receipt to persistent storage (RocksDB).
pub fn persist_receipt(db: &rocksdb::DB, receipt: &TxReceipt) {
    let key = format!("receipt:{}", receipt.tx_hash);
    if let Ok(data) = bincode::serialize(receipt) {
        if let Err(e) = db.put(key.as_bytes(), &data) {
            crate::slog_error!("receipt", "receipt_persist_failed",
                tx => &receipt.tx_hash, error => &e.to_string());
        }
    }
}

/// Load a receipt from persistent storage.
pub fn load_receipt(db: &rocksdb::DB, tx_hash: &str) -> Option<TxReceipt> {
    let key = format!("receipt:{}", tx_hash);
    match db.get(key.as_bytes()) {
        Ok(Some(data)) => bincode::deserialize(&data).ok(),
        _ => None,
    }
}

/// Persist multiple receipts in a batch write (more efficient for block-level writes).
pub fn persist_receipts_batch(db: &rocksdb::DB, receipts: &[TxReceipt]) {
    if receipts.is_empty() {
        return;
    }
    let mut batch = rocksdb::WriteBatch::default();
    for receipt in receipts {
        let key = format!("receipt:{}", receipt.tx_hash);
        if let Ok(data) = bincode::serialize(receipt) {
            batch.put(key.as_bytes(), &data);
        }
    }
    if let Err(e) = db.write(batch) {
        crate::slog_error!("receipt", "receipt_batch_persist_failed",
            count => &receipts.len().to_string(), error => &e.to_string());
    }
}

/// Delete receipts for a block's transactions (used during reorg rollback).
pub fn delete_receipts_for_block(db: &rocksdb::DB, tx_hashes: &[String]) {
    if tx_hashes.is_empty() {
        return;
    }
    let mut batch = rocksdb::WriteBatch::default();
    for tx_hash in tx_hashes {
        let key = format!("receipt:{}", tx_hash);
        batch.delete(key.as_bytes());
    }
    if let Err(e) = db.write(batch) {
        crate::slog_error!("receipt", "receipt_delete_failed",
            count => &tx_hashes.len().to_string(), error => &e.to_string());
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_receipt_is_pending() {
        let r = TxReceipt::new_pending("tx1".into(), 100, 2, 5000);
        assert_eq!(r.status, TxStatus::Pending);
        assert!(!r.status.is_confirmed());
    }

    #[test]
    fn status_transitions() {
        let mut r = TxReceipt::new_pending("tx1".into(), 100, 1, 1000);
        r.update_status(TxStatus::InMempool);
        r.set_in_block("block1", 10);
        assert!(matches!(r.status, TxStatus::InBlock { .. }));
        r.set_confirmed("block1", 10, 50);
        assert!(r.status.is_confirmed());
        assert!(!r.status.is_final());
        r.set_confirmed("block1", 10, 100);
        assert!(r.status.is_final());
    }

    #[test]
    fn store_track_and_get() {
        let store = ReceiptStore::new(1000);
        let r = TxReceipt::new_pending("tx1".into(), 50, 1, 500);
        store.track(r);
        let found = store.get("tx1").unwrap();
        assert_eq!(found.fee, 50);
    }

    #[test]
    fn store_update_status() {
        let store = ReceiptStore::new(1000);
        store.track(TxReceipt::new_pending("tx1".into(), 10, 1, 100));
        assert!(store.update_status("tx1", TxStatus::InMempool));
        let r = store.get("tx1").unwrap();
        assert_eq!(r.status, TxStatus::InMempool);
    }

    #[test]
    fn store_mark_in_block() {
        let store = ReceiptStore::new(1000);
        store.track(TxReceipt::new_pending("tx1".into(), 10, 1, 100));
        store.mark_in_block("tx1", "block_abc", 42);
        let r = store.get("tx1").unwrap();
        assert!(matches!(r.status, TxStatus::InBlock { block_height: 42, .. }));
    }

    #[test]
    fn rejected_is_failed() {
        let status = TxStatus::Rejected { reason: "double spend".into() };
        assert!(status.is_failed());
        assert!(!status.is_confirmed());
    }

    #[test]
    fn pending_list() {
        let store = ReceiptStore::new(1000);
        store.track(TxReceipt::new_pending("tx1".into(), 10, 1, 100));
        store.track(TxReceipt::new_pending("tx2".into(), 20, 1, 200));
        store.update_status("tx2", TxStatus::InMempool);
        assert_eq!(store.pending().len(), 2);
    }
}
