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
}

/// Log entry in a receipt (from contract execution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptLog {
    pub contract:  String,
    pub data:      String,
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
            receipt.set_confirmed(&bh, bht, confs);
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
