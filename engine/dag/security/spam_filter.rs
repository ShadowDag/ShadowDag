// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;

use crate::domain::block::block::Block;
use crate::domain::utxo::utxo_set::utxo_key;
use crate::engine::dag::security::dos_protection::MAX_BLOCK_TX_COUNT;

pub struct SpamFilter;

impl SpamFilter {
    #[inline(always)]
    pub fn validate(block: &Block) -> bool {
        let txs = &block.body.transactions;
        let len = txs.len();

        // 1️⃣ Empty block
        if len == 0 {
            return false;
        }

        // 2️⃣ Max tx count
        if len > MAX_BLOCK_TX_COUNT {
            return false;
        }

        let mut seen = HashSet::with_capacity(len);
        let mut coinbase_count = 0;

        for (i, tx) in txs.iter().enumerate() {
            // ❌ must have outputs
            if tx.outputs.is_empty() {
                return false;
            }

            // ❌ duplicate tx (يشمل الكوينبيس)
            if !seen.insert(&tx.hash) {
                return false;
            }

            let is_coinbase = tx.inputs.is_empty();

            // 🔥 coinbase rules
            if is_coinbase {
                coinbase_count += 1;

                if i != 0 {
                    return false;
                }
            } else {
                // 🔥 duplicate inputs (فقط لغير coinbase)
                let mut seen_inputs = HashSet::with_capacity(tx.inputs.len());
                for input in &tx.inputs {
                    match utxo_key(&input.txid, input.index) {
                        Ok(k) => {
                            if !seen_inputs.insert(k) {
                                return false;
                            }
                        }
                        Err(_) => return false,
                    }
                }
            }

            // 🔥 outputs checks (يشمل الجميع)
            let mut seen_outputs = HashSet::with_capacity(tx.outputs.len());
            let mut total: u128 = 0;

            for output in &tx.outputs {
                // ❌ zero output
                if output.amount == 0 {
                    return false;
                }

                // ❌ duplicate outputs
                let key = (&output.address, output.amount);
                if !seen_outputs.insert(key) {
                    return false;
                }

                // 🔥 overflow protection
                total = match total.checked_add(output.amount as u128) {
                    Some(v) => v,
                    None => return false,
                };
            }

            // ❌ overflow final check
            if total > u64::MAX as u128 {
                return false;
            }
        }

        // 🔥 exactly one coinbase
        if coinbase_count != 1 {
            return false;
        }

        true
    }
}
