use crate::domain::transaction::transaction::Transaction;
use crate::domain::transaction::tx_validator::TxValidator;
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::domain::utxo::utxo_validator::UtxoValidator;
use crate::service::mempool::core::mempool::Mempool;
use std::collections::HashSet;

pub struct TxPool {
    pub mempool: Mempool,
    pub spent_inputs: HashSet<UtxoKey>,
    pub seen_hashes: HashSet<String>,
}

impl TxPool {
    pub fn new(mempool: Mempool) -> Self {
        Self {
            mempool,
            spent_inputs: HashSet::new(),
            seen_hashes: HashSet::new(),
        }
    }

    pub fn add_transaction(&mut self, tx: &Transaction, utxo_set: &UtxoSet) -> TxPoolResult {
        if self.seen_hashes.contains(&tx.hash) {
            return TxPoolResult::Duplicate;
        }

        // Orphan management is centralized in MempoolManager::orphan_pool.
        // TxPool must not keep a second unbounded orphan cache.
        if !UtxoValidator::validate(tx, utxo_set) {
            return TxPoolResult::Orphan;
        }

        if !self.check_double_spend(tx) {
            return TxPoolResult::DoubleSpend;
        }

        if !TxValidator::validate_tx(tx, utxo_set) {
            return TxPoolResult::Invalid;
        }

        if !self.check_amount_overflow(tx) {
            return TxPoolResult::Invalid;
        }

        if !self.mempool.add_transaction(tx) {
            return TxPoolResult::Rejected;
        }

        self.mark_spent(tx);
        self.seen_hashes.insert(tx.hash.clone());

        TxPoolResult::Accepted
    }

    pub fn remove_transaction(&mut self, txid: &str) {
        // Clean up spent_inputs for this transaction's inputs
        if let Some(tx) = self.mempool.get_transaction(txid) {
            for input in &tx.inputs {
                if let Ok(key) = crate::domain::utxo::utxo_set::utxo_key(&input.txid, input.index)
                {
                    self.spent_inputs.remove(&key);
                }
            }
        }
        self.mempool.remove_transaction(txid);
        self.seen_hashes.remove(txid);
    }

    // Remove a transaction and all its dependents, cleaning up TxPool caches
    // (spent_inputs, seen_hashes) for each one.
    // mempool.remove_transaction cascades to dependents internally, but only
    // cleans up the top-level tx's TxPool caches. This method ensures every
    // recursively removed dependent also has its caches cleaned.
    pub fn remove_with_dependents(&mut self, txid: &str) {
        // First collect dependents before removing anything
        let deps = self.mempool.get_dependents(txid);
        // Remove the target first (cleans up its own caches)
        self.remove_transaction(txid);
        // Then remove each dependent (which cleans up their caches too)
        for dep_txid in &deps {
            self.remove_with_dependents(dep_txid);
        }
    }

    fn check_double_spend(&self, tx: &Transaction) -> bool {
        for input in &tx.inputs {
            match crate::domain::utxo::utxo_set::utxo_key(&input.txid, input.index) {
                Ok(key) => {
                    if self.spent_inputs.contains(&key) {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        true
    }

    fn check_amount_overflow(&self, tx: &Transaction) -> bool {
        let mut total: u128 = 0;
        for output in &tx.outputs {
            total = total.saturating_add(output.amount as u128);
            if total > u64::MAX as u128 {
                return false;
            }
        }
        true
    }

    fn mark_spent(&mut self, tx: &Transaction) {
        for input in &tx.inputs {
            if let Ok(key) = crate::domain::utxo::utxo_set::utxo_key(&input.txid, input.index) {
                self.spent_inputs.insert(key);
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum TxPoolResult {
    Accepted,
    Duplicate,
    Orphan,
    DoubleSpend,
    Invalid,
    Rejected,
}
