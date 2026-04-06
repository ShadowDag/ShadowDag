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

pub struct BlockBuilder;

impl BlockBuilder {
    /// Build a block from mempool transactions WITH a pre-built coinbase.
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
    ) -> Block {
        assert!(coinbase.is_coinbase(), "First transaction must be a coinbase");

        // Reserve one slot for coinbase
        let mempool_txs: Vec<Transaction> =
            tx_pool.get_prioritized_txs(max_txs.saturating_sub(1));

        // Coinbase first, then mempool transactions
        let mut all_txs = vec![coinbase];
        all_txs.extend(mempool_txs);

        let tx_hashes: Vec<String> = all_txs.iter().map(|tx| tx.hash.clone()).collect();
        let merkle_root = MerkleTree::calculate_root(tx_hashes);

        let selected_parent = parents.first().cloned();

        let header = BlockHeader {
            version,
            hash:            String::new(),
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
        };

        let body = BlockBody { transactions: all_txs };

        Block { header, body }
    }
}
