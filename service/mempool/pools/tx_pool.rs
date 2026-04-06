// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashSet, HashMap};
use crate::service::mempool::core::mempool::Mempool;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::domain::transaction::tx_validator::TxValidator;
use crate::domain::utxo::utxo_validator::UtxoValidator;

pub struct TxPool {
    pub mempool:        Mempool,
    pub spent_inputs:   HashSet<UtxoKey>,
    pub seen_hashes:    HashSet<String>,
    pub orphan_parents: HashMap<String, Vec<Transaction>>,
}

impl TxPool {
    pub fn new(mempool: Mempool) -> Self {
        Self {
            mempool,
            spent_inputs:   HashSet::new(),
            seen_hashes:    HashSet::new(),
            orphan_parents: HashMap::new(),
        }
    }

    pub fn add_transaction(&mut self, tx: &Transaction, utxo_set: &UtxoSet) -> TxPoolResult {
        if self.seen_hashes.contains(&tx.hash) {
            return TxPoolResult::Duplicate;
        }

        if !UtxoValidator::validate(tx, utxo_set) {
            self.add_to_orphan_pool(tx);
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

        self.promote_orphans(&tx.hash, utxo_set);

        TxPoolResult::Accepted
    }

    pub fn remove_transaction(&mut self, txid: &str) {
        // Clean up spent_inputs for this transaction's inputs
        if let Some(tx) = self.mempool.get_transaction(txid) {
            for input in &tx.inputs {
                if let Ok(key) = crate::domain::utxo::utxo_set::utxo_key(&input.txid, input.index) {
                    self.spent_inputs.remove(&key);
                }
            }
        }
        self.mempool.remove_transaction(txid);
        self.seen_hashes.remove(txid);
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

    fn add_to_orphan_pool(&mut self, tx: &Transaction) {
        for input in &tx.inputs {
            self.orphan_parents
                .entry(input.txid.clone())
                .or_default()
                .push(tx.clone());
        }
    }

    fn promote_orphans(&mut self, parent_txid: &str, utxo_set: &UtxoSet) {
        if let Some(orphans) = self.orphan_parents.remove(parent_txid) {
            for orphan in orphans {
                if UtxoValidator::validate(&orphan, utxo_set)
                    && TxValidator::validate_tx(&orphan, utxo_set) {
                    let _ = self.mempool.add_transaction(&orphan);
                    self.mark_spent(&orphan);
                    self.seen_hashes.insert(orphan.hash.clone());
                }
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
