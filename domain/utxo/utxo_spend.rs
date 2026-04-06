// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::collections::HashSet;

use crate::domain::transaction::transaction::Transaction;
use crate::domain::utxo::utxo::Utxo;
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_set::{BlockUndoData, UtxoSet, utxo_key};
use crate::slog_warn;

pub struct UtxoSpend;

impl UtxoSpend {
    pub fn apply_transaction(tx: &Transaction, utxo_set: &UtxoSet) -> bool {
        for input in &tx.inputs {
            let key = match utxo_key(&input.txid, input.index) {
                Ok(k) => k,
                Err(_) => return false,
            };
            if !utxo_set.exists(&key) {
                return false;
            }
        }

        for input in &tx.inputs {
            let key = match utxo_key(&input.txid, input.index) {
                Ok(k) => k,
                Err(_) => return false,
            };
            utxo_set.spend_utxo(&key);
        }

        for (index, output) in tx.outputs.iter().enumerate() {
            let key = match utxo_key(&tx.hash, index as u32) {
                Ok(k) => k,
                Err(_) => return false,
            };
            utxo_set.add_utxo(
                &key,
                output.address.clone(),
                output.amount,
                output.address.clone(),
            );
        }

        true
    }

    pub fn apply_block_atomic(transactions: &[Transaction], utxo_set: &UtxoSet) -> bool {
        let mut will_be_spent: HashSet<UtxoKey> = HashSet::new();

        for tx in transactions {
            if tx.is_coinbase() {
                continue;
            }

            for input in &tx.inputs {
                let key = match utxo_key(&input.txid, input.index) {
                    Ok(k) => k,
                    Err(_) => return false,
                };

                if will_be_spent.contains(&key) {
                    return false;
                }

                if !utxo_set.exists(&key) {
                    return false;
                }

                will_be_spent.insert(key);
            }
        }

        for tx in transactions {
            Self::apply_transaction(tx, utxo_set);
        }

        true
    }

    /// Rollback a block: remove outputs and restore spent inputs.
    /// Processes transactions in reverse order for correctness.
    ///
    /// `undo_data` contains the original UTXOs that were spent by this block,
    /// keyed by their string representation ("txhash:index"), so we can
    /// restore the correct amounts and addresses instead of zeroes.
    pub fn rollback_block(
        transactions: &[Transaction],
        utxo_set: &UtxoSet,
        undo_data: &BlockUndoData,
    ) {
        // Build a lookup map from the undo data for O(1) access by key string.
        let spent_map: HashMap<&str, &Utxo> = undo_data
            .spent_utxos
            .iter()
            .map(|(k, u)| (k.as_str(), u))
            .collect();

        for tx in transactions.iter().rev() {
            // 1. Remove all outputs created by this transaction (mark as spent)
            for (idx, _output) in tx.outputs.iter().enumerate() {
                if let Ok(key) = utxo_key(&tx.hash, idx as u32) {
                    utxo_set.spend_utxo(&key);
                }
            }

            // 2. Restore inputs that were consumed (unspend them)
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    if let Ok(key) = utxo_key(&input.txid, input.index) {
                        let key_str = format!("{}:{}", input.txid, input.index);
                        if let Some(original) = spent_map.get(key_str.as_str()) {
                            // Restore from undo data with correct amount and address
                            utxo_set.add_utxo(
                                &key,
                                original.owner.clone(),
                                original.amount,
                                original.address.clone(),
                            );
                        } else {
                            // Undo data missing for this input — log and skip.
                            // This should not happen if undo data was recorded correctly.
                            slog_warn!("utxo", "rollback_missing_undo_data", input => &key_str);
                        }
                    }
                }
            }
        }
    }
}
