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

        // Coinbase first, then mempool transactions
        let mut all_txs = vec![coinbase];
        all_txs.extend(mempool_txs);

        #[allow(deprecated)]
        let merkle_root = {
            let tx_hashes: Vec<String> = all_txs.iter().map(|tx| tx.hash.clone()).collect();
            MerkleTree::calculate_root(tx_hashes)
        };

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
