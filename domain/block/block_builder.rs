// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block::Block;
use crate::domain::block::block_body::BlockBody;
use crate::domain::block::block_header::BlockHeader;
use crate::domain::block::merkle_tree::MerkleTree;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::traits::tx_pool::TxPool;
use crate::config::consensus::consensus_params::ConsensusParams;

pub struct BlockBuilder;

impl BlockBuilder {
    /// Build a block TEMPLATE (hash is empty -- must be set by miner after PoW).
    ///
    /// The returned block is NOT valid for consensus until the miner fills in:
    /// - `header.hash` (computed via ShadowHash)
    /// - `header.nonce` / `header.extra_nonce` (found via mining)
    ///
    /// The coinbase MUST be provided by the caller (from Miner or BlockTemplateBuilder)
    /// because the validator requires: block.body.transactions[0].is_coinbase() == true.
    ///
    /// For production block building, prefer `BlockTemplateBuilder::build_from_dag()`
    /// which handles coinbase creation, fee calculation, and DAG parent selection.
    #[allow(clippy::too_many_arguments)]
    pub fn build_block(
        version:    u32,
        height:     u64,
        parents:    Vec<String>,
        coinbase:   Transaction,
        tx_pool:    &dyn TxPool,
        max_txs:    usize,
        difficulty: u64,
        timestamp:  u64,
    ) -> Result<Block, String> {
        if !coinbase.is_coinbase() {
            return Err("first transaction must be coinbase".to_string());
        }

        // Non-genesis blocks MUST have parents
        if height > 0 && parents.is_empty() {
            return Err("non-genesis block requires at least one parent".to_string());
        }

        // Reserve one slot for coinbase
        let mempool_txs: Vec<Transaction> =
            tx_pool.get_prioritized_txs(max_txs.saturating_sub(1));

        // Coinbase first, then mempool transactions filtered by block gas budget
        let mut all_txs = vec![coinbase];
        let mut block_gas_used: u64 = 0;
        let max_block_gas = ConsensusParams::MAX_BLOCK_GAS;

        for tx in mempool_txs {
            let tx_gas = tx.gas_limit.unwrap_or(0);
            if tx_gas > 0 {
                // BUG FIX: Use checked_add to prevent overflow.
                // A malicious TX with gas_limit near u64::MAX could wrap
                // block_gas_used, bypassing the block gas limit entirely.
                let new_gas = match block_gas_used.checked_add(tx_gas) {
                    Some(g) => g,
                    None => break, // overflow — treat as limit reached
                };
                if new_gas > max_block_gas {
                    break; // Block gas limit reached
                }
                block_gas_used = new_gas;
            }
            all_txs.push(tx);
        }

        let merkle_root = MerkleTree::build(
            &all_txs,
            height,
            &parents,
        );

        let selected_parent = parents.first().cloned();

        let header = BlockHeader {
            version,
            hash:            String::new(),  // Template: filled by miner after PoW
            parents,
            merkle_root,
            timestamp,
            nonce:           0,
            difficulty,
            height,
            blue_score:      0,
            selected_parent,
            utxo_commitment: None,
            extra_nonce:     0,
            receipt_root:    None,
            state_root:      None,
        };

        let body = BlockBody { transactions: all_txs };

        Ok(Block { header, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput};
    use crate::domain::utxo::utxo_set::UtxoSet;

    /// Empty TxPool that always returns no transactions.
    struct EmptyPool;

    impl TxPool for EmptyPool {
        fn get_transaction(&self, _hash: &str) -> Option<Transaction> { None }
        fn has_transaction(&self, _hash: &str) -> bool { false }
        fn count(&self) -> usize { 0 }
        fn get_prioritized_txs(&self, _limit: usize) -> Vec<Transaction> { vec![] }
        fn get_transactions_for_block(&self, _utxo: &UtxoSet, _max: usize) -> Vec<Transaction> { vec![] }
    }

    fn make_coinbase(hash: &str) -> Transaction {
        Transaction::new_coinbase(
            hash.to_string(),
            vec![TxOutput::new("miner".into(), 5000)],
            0,
            1735689600,
        )
    }

    #[test]
    fn empty_blocks_at_different_heights_have_different_merkle_roots() {
        let pool = EmptyPool;
        let coinbase_10 = make_coinbase("aa".repeat(32).as_str());
        let coinbase_20 = make_coinbase("ab".repeat(32).as_str());
        let parents = vec!["bb".repeat(32)];

        let block1 = BlockBuilder::build_block(
            1, 10, parents.clone(), coinbase_10, &pool, 100, 1, 1735689600
        ).expect("build height=10");

        let block2 = BlockBuilder::build_block(
            1, 20, parents, coinbase_20, &pool, 100, 1, 1735689600
        ).expect("build height=20");

        assert_ne!(
            block1.header.merkle_root, block2.header.merkle_root,
            "Blocks at different heights must have different merkle roots (MerkleTree::build includes height)"
        );
    }

    #[test]
    fn empty_blocks_with_different_parents_have_different_merkle_roots() {
        let pool = EmptyPool;
        let coinbase_a = make_coinbase("aa".repeat(32).as_str());
        let coinbase_b = make_coinbase("ac".repeat(32).as_str());

        let block1 = BlockBuilder::build_block(
            1, 10, vec!["parent_a".repeat(8)], coinbase_a, &pool, 100, 1, 1735689600
        ).expect("build parent_a");

        let block2 = BlockBuilder::build_block(
            1, 10, vec!["parent_b".repeat(8)], coinbase_b, &pool, 100, 1, 1735689600
        ).expect("build parent_b");

        assert_ne!(
            block1.header.merkle_root, block2.header.merkle_root,
            "Blocks with different parents must have different merkle roots"
        );
    }
}
