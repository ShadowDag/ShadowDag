// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// MinerController — Orchestrates the mining loop by connecting the miner
// to the DAG tip manager, mempool, and UTXO set.
//
// Responsibilities:
//   - Query DAG tips for parent selection (via TipManager)
//   - Validate parents exist in DAG (via DagManager)
//   - Build block templates with proper coinbase (emission schedule + 5% dev fee)
//   - Pull and validate mempool transactions against UTXO state
//   - Submit mined blocks back to the DAG
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{Options, DB};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::block::block::Block;
use crate::domain::traits::tx_pool::TxPool;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::engine::dag::core::dag_manager::DagManager;
use crate::engine::dag::tips::tip_manager::TipManager;
use crate::engine::mining::miner::block_template::BlockTemplateBuilder;
use crate::engine::mining::miner::miner::Miner;
use crate::errors::ConsensusError;
use crate::{slog_error, slog_info};

pub struct MinerControllerStore {
    db: DB,
}

impl MinerControllerStore {
    pub fn new(path: &str) -> Result<Self, crate::errors::StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path)).map_err(|e| {
            crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            }
        })?;

        Ok(Self { db })
    }

    pub fn store_job(&self, id: &str, job: &str) {
        if let Err(_e) = self.db.put(id, job) {
            slog_error!("mining", "controller_store_put_failed", error => _e);
        }
    }
}

/// MinerController connects the miner to the DAG.
///
/// It queries current DAG tips, builds block templates with proper parent
/// selection (highest blue scores, capped at MAX_PARENTS), validates parents
/// exist, pulls mempool transactions, and creates coinbase with the correct
/// emission reward including the 5% dev fee split.
pub struct MinerController<'a> {
    pub miner: &'a Miner,
    pub tip_manager: &'a TipManager,
    pub dag_manager: &'a DagManager,
    pub mempool: &'a dyn TxPool,
    pub utxo_set: &'a UtxoSet,
}

impl<'a> MinerController<'a> {
    pub fn new(
        miner: &'a Miner,
        tip_manager: &'a TipManager,
        dag_manager: &'a DagManager,
        mempool: &'a dyn TxPool,
        utxo_set: &'a UtxoSet,
    ) -> Self {
        Self {
            miner,
            tip_manager,
            dag_manager,
            mempool,
            utxo_set,
        }
    }

    /// Build a block template from current DAG tips and mine it.
    ///
    /// Steps:
    /// 1. Query TipManager for current DAG tips (sorted by blue score)
    /// 2. Select top tips as parents (capped at MAX_PARENTS = 8)
    /// 3. Validate all parent blocks exist in DagManager
    /// 4. Pull transactions from mempool, validate against UTXO state
    /// 5. Create coinbase with emission schedule reward + 5% dev fee
    /// 6. Mine the block (find valid nonce via PoW)
    /// 7. Return the mined block for submission to the DAG
    pub fn build_and_mine(&self, miner_address: &str) -> Result<Block, ConsensusError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Avoid process-global difficulty state here. Controllers should use
        // the miner instance difficulty configured by the node that owns this
        // controller.
        let current_difficulty = self.miner.difficulty.max(1);

        // Build template using DAG tips as parents
        let block = BlockTemplateBuilder::build_from_dag(
            self.tip_manager,
            self.dag_manager,
            self.mempool,
            self.utxo_set,
            miner_address,
            timestamp,
            current_difficulty,
        )?;

        slog_info!("mining", "template_built", height => block.header.height, parents => block.header.parents.len(), txs => block.body.transactions.len());

        // Validate parents before mining
        Miner::validate_parents(&block, self.dag_manager)?;

        // Mine the block
        let mined_block = self.miner.mine_block(block);

        if mined_block.header.hash.is_empty() {
            return Err(ConsensusError::Other(
                "nonce space exhausted — request new template".to_string(),
            ));
        }

        Ok(mined_block)
    }

    /// After mining, submit the block to the DAG and update tip set.
    pub fn submit_block(&self, block: &Block) -> Result<(), ConsensusError> {
        // Add block to DAG — topology/PoW validation only.
        // NOTE: Full consensus validation (UTXO, coinbase, contracts)
        // happens when process_block routes through the FullNode pipeline.
        // MinerController's DAG insertion is the first step; the daemon
        // event loop picks up the block from PENDING_BLOCKS for full
        // validation. Direct callers of submit_block should be aware
        // that UTXO/contract state is NOT verified here.
        self.dag_manager.add_block(block)?;

        // Update tip manager: remove parents from tips, add new block as tip
        self.tip_manager.on_new_block(
            &block.header.hash,
            &block.header.parents,
            block.header.blue_score,
            block.header.height,
            block.header.timestamp,
        )?;

        slog_info!("mining", "block_submitted_to_dag", hash_prefix => &block.header.hash[..block.header.hash.len().min(16)], height => block.header.height, tips => self.tip_manager.tip_count());

        Ok(())
    }

    /// Full mining cycle: build template, mine, submit to DAG.
    pub fn mine_and_submit(&self, miner_address: &str) -> Result<Block, ConsensusError> {
        let block = self.build_and_mine(miner_address)?;
        self.submit_block(&block)?;
        Ok(block)
    }
}
