// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use crate::domain::block::block::Block;
use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
use crate::engine::mining::algorithms::shadowhash::shadow_hash;
use crate::engine::mining::pow::pow_validator::PowValidator;
use crate::engine::dag::core::dag_manager::DagManager;
use crate::engine::dag::security::dos_protection::MAX_DAG_PARENTS;
use crate::errors::ConsensusError;

pub struct Miner {
    pub difficulty:           u64,
    pub block_reward:         u64,
    pub owner_reward_address: String,
}

impl Miner {
    pub fn new(difficulty: u64, owner_reward_address: String) -> Self {
        Self {
            difficulty,
            block_reward: crate::config::consensus::emission_schedule::INITIAL_REWARD,
            owner_reward_address,
        }
    }

    pub fn create_coinbase(
        &self,
        miner_address: String,
        timestamp: u64,
        height: u64,
    ) -> Transaction {
        self.create_coinbase_with_fees(miner_address, timestamp, height, 0)
    }

    /// Build a coinbase transaction that includes both emission reward and tx fees.
    /// The validator requires: coinbase total == emission + total_fees.
    pub fn create_coinbase_with_fees(
        &self,
        miner_address: String,
        timestamp: u64,
        height: u64,
        total_fees: u64,
    ) -> Transaction {
        let emission = crate::config::consensus::emission_schedule::EmissionSchedule::block_reward(height);
        let reward = emission.saturating_add(total_fees);
        let miner_reward = (reward * crate::config::consensus::consensus_params::ConsensusParams::MINER_PERCENT) / 100;
        let owner_reward = reward - miner_reward;

        let hash = Self::coinbase_hash(&miner_address, timestamp, height);

        Transaction {
            hash,
            inputs: vec![],
            outputs: vec![
                TxOutput { address: miner_address,                    amount: miner_reward, commitment: None, range_proof: None, ephemeral_pubkey: None },
                TxOutput { address: self.owner_reward_address.clone(), amount: owner_reward, commitment: None, range_proof: None, ephemeral_pubkey: None },
            ],
            fee:         0,
            timestamp,
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    pub fn coinbase_hash(miner_address: &str, timestamp: u64, height: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"coinbase");
        h.update(miner_address.as_bytes());
        h.update(timestamp.to_le_bytes());
        h.update(height.to_le_bytes());
        hex::encode(h.finalize())
    }

    /// Validate that all parent blocks exist in the DAG and enforce max parents limit.
    /// Returns Ok(()) if all parents are valid, Err with description otherwise.
    pub fn validate_parents(
        block: &Block,
        dag_manager: &DagManager,
    ) -> Result<(), ConsensusError> {
        let parents = &block.header.parents;

        // Non-genesis blocks must have parents
        if block.header.height > 0 && parents.is_empty() {
            return Err(ConsensusError::Other("Block has no parents (non-genesis blocks require at least one parent)".to_string()));
        }

        // Enforce max parents limit
        if parents.len() > MAX_DAG_PARENTS {
            return Err(ConsensusError::Other(format!(
                "Block has {} parents, exceeding max of {}",
                parents.len(), MAX_DAG_PARENTS
            )));
        }

        // Check for duplicate parents
        let mut seen = std::collections::HashSet::with_capacity(parents.len());
        for parent in parents {
            if !seen.insert(parent.as_str()) {
                return Err(ConsensusError::Other(format!("Duplicate parent: {}", parent)));
            }
        }

        // Verify all parent blocks exist in the DAG
        for parent_hash in parents {
            if !dag_manager.block_exists(parent_hash) {
                return Err(ConsensusError::Other(format!(
                    "Parent block {} not found in DAG",
                    &parent_hash[..parent_hash.len().min(16)]
                )));
            }
        }

        // Self-referential check
        for parent in parents {
            if parent == &block.header.hash && !block.header.hash.is_empty() {
                return Err(ConsensusError::Other("Block cannot be its own parent".to_string()));
            }
        }

        Ok(())
    }

    /// Mine a block, validating parents against the DAG before starting.
    pub fn mine_block_validated(
        &self,
        block: Block,
        dag_manager: &DagManager,
    ) -> Result<Block, ConsensusError> {
        Self::validate_parents(&block, dag_manager)?;
        Ok(self.mine_block(block))
    }

    pub fn mine_block(&self, mut block: Block) -> Block {
        let mut nonce: u64 = 0;
        let base_timestamp = block.header.timestamp;
        let mut ts_bumps = 0u32;

        eprintln!(
            "Miner → start mining height={} parents={} difficulty={}",
            block.header.height,
            block.header.parents.len(),
            self.difficulty
        );

        loop {
            block.header.nonce = nonce;
            let hash = shadow_hash(&block);

            if PowValidator::hash_meets_target(&hash, self.difficulty) {
                block.header.hash = hash.clone();
                eprintln!(
                    "Miner → block FOUND nonce={} hash={} height={} parents={}",
                    nonce,
                    &hash[..8],
                    block.header.height,
                    block.header.parents.len()
                );
                return block;
            }

            nonce = nonce.wrapping_add(1);

            // When primary nonce wraps, increment extra_nonce for fresh hash domain.
            // This provides 2^128 total nonce space (2^64 × 2^64).
            if nonce == 0 {
                block.header.extra_nonce = block.header.extra_nonce.wrapping_add(1);
                if block.header.extra_nonce == 0 {
                    // Both nonce spaces exhausted — bump timestamp as last resort
                    ts_bumps += 1;
                    if ts_bumps > 100 {
                        return block; // Give up, request new template
                    }
                    block.header.timestamp = base_timestamp + ts_bumps as u64;
                }
            }

            if nonce.is_multiple_of(1_000_000) {
                eprintln!(
                    "Miner → nonce={} (mining height={})",
                    nonce, block.header.height
                );
            }
        }
    }

    pub fn verify_pow(block: &Block) -> bool {
        let computed = shadow_hash(block);
        if computed != block.header.hash {
            eprintln!(
                "[Miner] PoW mismatch: computed={} stored={}",
                &computed[..8],
                &block.header.hash.get(..8).unwrap_or("?")
            );
            return false;
        }
        PowValidator::hash_meets_target(&computed, block.header.difficulty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coinbase_hash_is_deterministic() {
        let h1 = Miner::coinbase_hash("shadow1abc", 1735689600, 1);
        let h2 = Miner::coinbase_hash("shadow1abc", 1735689600, 1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn coinbase_hash_differs_by_height() {
        let h1 = Miner::coinbase_hash("shadow1abc", 1735689600, 1);
        let h2 = Miner::coinbase_hash("shadow1abc", 1735689600, 2);
        assert_ne!(h1, h2);
    }
}
