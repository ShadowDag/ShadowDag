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

use rocksdb::{DB, Options};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::block::block::Block;
use crate::engine::mining::miner::miner::Miner;
use crate::engine::mining::miner::block_template::BlockTemplateBuilder;
use crate::engine::dag::tips::tip_manager::TipManager;
use crate::engine::dag::core::dag_manager::DagManager;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::domain::traits::tx_pool::TxPool;
use crate::errors::ConsensusError;

pub struct MinerControllerStore {
    db: DB,
}

impl MinerControllerStore {
    pub fn new(path: &str) -> Result<Self, crate::errors::StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            })?;

        Ok(Self { db })
    }

    pub fn store_job(&self, id: &str, job: &str) {
        if let Err(_e) = self.db.put(id, job) { eprintln!("[DB] put error: {}", _e); }
    }
}

/// MinerController connects the miner to the DAG.
///
/// It queries current DAG tips, builds block templates with proper parent
/// selection (highest blue scores, capped at MAX_PARENTS), validates parents
/// exist, pulls mempool transactions, and creates coinbase with the correct
/// emission reward including the 5% dev fee split.
pub struct MinerController<'a> {
    pub miner:       &'a Miner,
    pub tip_manager: &'a TipManager,
    pub dag_manager: &'a DagManager,
    pub mempool:     &'a dyn TxPool,
    pub utxo_set:    &'a UtxoSet,
}

impl<'a> MinerController<'a> {
    pub fn new(
        miner:       &'a Miner,
        tip_manager: &'a TipManager,
        dag_manager: &'a DagManager,
        mempool:     &'a dyn TxPool,
        utxo_set:    &'a UtxoSet,
    ) -> Self {
        Self { miner, tip_manager, dag_manager, mempool, utxo_set }
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
    pub fn build_and_mine(
        &self,
        miner_address: &str,
    ) -> Result<Block, ConsensusError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build template using DAG tips as parents
        let block = BlockTemplateBuilder::build_from_dag(
            self.tip_manager,
            self.dag_manager,
            self.mempool,
            self.utxo_set,
            miner_address,
            timestamp,
            self.miner.difficulty,
        )?;

        eprintln!(
            "[MinerController] Template built: height={} parents={} txs={}",
            block.header.height,
            block.header.parents.len(),
            block.body.transactions.len(),
        );

        // Validate parents before mining
        Miner::validate_parents(&block, self.dag_manager)?;

        // Mine the block
        let mined_block = self.miner.mine_block(block);

        Ok(mined_block)
    }

    /// After mining, submit the block to the DAG and update tip set.
    pub fn submit_block(&self, block: &Block) -> Result<(), ConsensusError> {
        // Add block to DAG (validates parents again internally)
        self.dag_manager.add_block(block)?;

        // Update tip manager: remove parents from tips, add new block as tip
        self.tip_manager.on_new_block(
            &block.header.hash,
            &block.header.parents,
            block.header.blue_score,
            block.header.height,
            block.header.timestamp,
        );

        eprintln!(
            "[MinerController] Block submitted to DAG: hash={}... height={} tips={}",
            &block.header.hash[..block.header.hash.len().min(16)],
            block.header.height,
            self.tip_manager.tip_count(),
        );

        Ok(())
    }

    /// Full mining cycle: build template, mine, submit to DAG.
    pub fn mine_and_submit(
        &self,
        miner_address: &str,
    ) -> Result<Block, ConsensusError> {
        let block = self.build_and_mine(miner_address)?;
        self.submit_block(&block)?;
        Ok(block)
    }
}
