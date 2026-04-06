// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{HashMap, HashSet, VecDeque};
use crate::domain::block::block::Block;
use crate::domain::block::block_header::BlockHeader;
use crate::domain::block::block_body::BlockBody;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::transaction::tx_builder::{build_coinbase_at_height};
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_set::{UtxoSet, utxo_key};
use crate::domain::transaction::tx_validator::TxValidator;
use crate::domain::traits::tx_pool::TxPool;
use crate::config::consensus::consensus_params::ConsensusParams;
use crate::config::consensus::emission_schedule::EmissionSchedule;
use crate::engine::dag::tips::tip_manager::TipManager;
use crate::engine::dag::core::dag_manager::DagManager;
use crate::engine::dag::security::dos_protection::{MAX_DAG_PARENTS, MAX_BLOCK_TX_COUNT};
use crate::errors::ConsensusError;

pub struct BlockTemplateBuilder;

pub struct BlockTemplate {
    pub transactions: Vec<Transaction>,
    pub total_fees:   u64,
    pub tx_count:     usize,
}

impl BlockTemplateBuilder {
    /// Select parents from DAG tips, validate they exist, enforce max_parents limit.
    /// Tips are selected by highest blue score (from TipManager::select_parents).
    /// All selected parents are verified to exist in the DAG.
    pub fn select_dag_parents(
        tip_manager: &TipManager,
        dag_manager: &DagManager,
    ) -> Result<Vec<String>, ConsensusError> {
        let max_parents = ConsensusParams::MAX_PARENTS.min(MAX_DAG_PARENTS);

        // Select tips sorted by blue score (highest first), capped at max_parents
        let candidates = tip_manager.select_parents(max_parents);

        if candidates.is_empty() {
            return Err(ConsensusError::Other("No DAG tips available for parent selection".to_string()));
        }

        // Validate all parent blocks exist in the DAG
        let mut validated_parents: Vec<String> = Vec::with_capacity(candidates.len());
        for parent_hash in &candidates {
            if !dag_manager.block_exists(parent_hash) {
                eprintln!(
                    "[BlockTemplate] WARNING: tip {} not found in DAG, skipping",
                    &parent_hash[..parent_hash.len().min(16)]
                );
                continue;
            }
            validated_parents.push(parent_hash.clone());
        }

        if validated_parents.is_empty() {
            return Err(ConsensusError::Other("No valid parent blocks found in DAG".to_string()));
        }

        Ok(validated_parents)
    }

    /// Build a block template using current DAG tips as parents.
    /// This is the primary entry point that properly connects mining to the DAG.
    pub fn build_from_dag(
        tip_manager:   &TipManager,
        dag_manager:   &DagManager,
        mempool:       &dyn TxPool,
        utxo_set:      &UtxoSet,
        miner_address: &str,
        timestamp:     u64,
        difficulty:    u64,
    ) -> Result<Block, ConsensusError> {
        let parents = Self::select_dag_parents(tip_manager, dag_manager)?;

        // Height = best tip height + 1
        let best_height = tip_manager.best_height();
        let height = best_height + 1;

        // Pull transactions from mempool, validate against current UTXO state
        // NOTE: must select transactions BEFORE building coinbase so we know total fees.
        let candidates = mempool.get_transactions_for_block(
            utxo_set,
            MAX_BLOCK_TX_COUNT - 1, // reserve slot for coinbase
        );

        let template = Self::select_valid_transactions(candidates, utxo_set);

        // Coinbase reward = emission + transaction fees (must match validator expectation)
        let emission = EmissionSchedule::block_reward(height);
        let reward   = emission.saturating_add(template.total_fees);

        let coinbase = build_coinbase_at_height(
            miner_address.to_string(),
            ConsensusParams::OWNER_REWARD_ADDRESS.to_string(),
            reward,
            ConsensusParams::MINER_PERCENT,
            timestamp,
            height,
        );

        let merkle_root = Self::compute_merkle_root(&coinbase, &template.transactions, height, &parents);

        // Selected parent = the one with highest blue score (first in our sorted list)
        let selected_parent = Some(parents[0].clone());

        let header = BlockHeader {
            version:         1,
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

        let mut all_txs = vec![coinbase];
        all_txs.extend(template.transactions);

        Ok(Block {
            header,
            body: BlockBody { transactions: all_txs },
        })
    }

    /// Legacy build method — accepts explicit parents (kept for backward compatibility).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        mempool:       &dyn TxPool,
        utxo_set:      &UtxoSet,
        miner_address: &str,
        height:        u64,
        timestamp:     u64,
        parents:       Vec<String>,
        difficulty:    u64,
        _prev_hash:    &str,
    ) -> Block {
        // Select transactions BEFORE building coinbase so we know total fees
        let candidates = mempool.get_transactions_for_block(
            utxo_set,
            MAX_BLOCK_TX_COUNT - 1
        );

        let template = Self::select_valid_transactions(candidates, utxo_set);

        // Coinbase reward = emission + transaction fees (must match validator expectation)
        let emission = EmissionSchedule::block_reward(height);
        let reward   = emission.saturating_add(template.total_fees);

        let coinbase = build_coinbase_at_height(
            miner_address.to_string(),
            ConsensusParams::OWNER_REWARD_ADDRESS.to_string(),
            reward,
            ConsensusParams::MINER_PERCENT,
            timestamp,
            height,
        );

        let merkle_root = Self::compute_merkle_root(&coinbase, &template.transactions, height, &parents);

        let selected_parent = parents.first().cloned();

        let header = BlockHeader {
            version:         1,
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

        let mut all_txs = vec![coinbase];
        all_txs.extend(template.transactions);

        Block {
            header,
            body: BlockBody { transactions: all_txs },
        }
    }

    fn select_valid_transactions(
        candidates:  Vec<Transaction>,
        utxo_set:    &UtxoSet,
    ) -> BlockTemplate {
        let mut staged_utxos: HashMap<UtxoKey, (String, u64)> = HashMap::new();

        let mut spent_in_block: HashSet<UtxoKey> = HashSet::new();

        let mut accepted: Vec<Transaction> = Vec::new();
        let mut total_fees: u64 = 0;

        let sorted = Self::topological_sort(candidates);

        for tx in sorted {
            let mut conflict = false;
            let mut bad_key = false;
            for input in &tx.inputs {
                match utxo_key(&input.txid, input.index) {
                    Ok(key) => {
                        if spent_in_block.contains(&key) {
                            conflict = true;
                            break;
                        }
                    }
                    Err(_) => { bad_key = true; break; }
                }
            }
            if bad_key || conflict { continue; }

            let mut utxo_ok = true;
            for input in &tx.inputs {
                match utxo_key(&input.txid, input.index) {
                    Ok(key) => {
                        let in_real = utxo_set.exists(&key);
                        let in_staged = staged_utxos.contains_key(&key);
                        if !in_real && !in_staged {
                            utxo_ok = false;
                            break;
                        }
                    }
                    Err(_) => { utxo_ok = false; break; }
                }
            }
            if !utxo_ok { continue; }

            if !tx.is_coinbase()
                && !TxValidator::validate_tx(&tx, utxo_set) {
                    let all_staged = tx.inputs.iter().all(|i| {
                        match utxo_key(&i.txid, i.index) {
                            Ok(k) => staged_utxos.contains_key(&k),
                            Err(_) => false,
                        }
                    });
                    if !all_staged {
                        continue;
                    }
                }

            let mut skip = false;
            for input in &tx.inputs {
                match utxo_key(&input.txid, input.index) {
                    Ok(key) => { spent_in_block.insert(key); }
                    Err(_) => { skip = true; break; }
                }
            }
            if skip { continue; }

            for (idx, output) in tx.outputs.iter().enumerate() {
                match utxo_key(&tx.hash, idx as u32) {
                    Ok(key) => { staged_utxos.insert(key, (output.address.clone(), output.amount)); }
                    Err(_) => { skip = true; break; }
                }
            }
            if skip { continue; }

            total_fees += tx.fee;
            accepted.push(tx);
        }

        BlockTemplate {
            tx_count:     accepted.len(),
            total_fees,
            transactions: accepted,
        }
    }

    fn topological_sort(txs: Vec<Transaction>) -> Vec<Transaction> {
        let mut tx_map: HashMap<String, Transaction> = HashMap::new();
        for tx in &txs {
            tx_map.insert(tx.hash.clone(), tx.clone());
        }

        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut edges: HashMap<String, Vec<String>> = HashMap::new();

        for tx in &txs {
            in_degree.entry(tx.hash.clone()).or_insert(0);
            for input in &tx.inputs {
                if tx_map.contains_key(&input.txid) {
                    *in_degree.entry(tx.hash.clone()).or_insert(0) += 1;
                    edges.entry(input.txid.clone()).or_default().push(tx.hash.clone());
                }
            }
        }

        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(h, _)| h.clone())
            .collect();

        let mut result: Vec<Transaction> = Vec::new();

        while let Some(hash) = queue.pop_front() {
            if let Some(tx) = tx_map.remove(&hash) {
                if let Some(dependents) = edges.get(&hash) {
                    for dep in dependents {
                        let d = in_degree.entry(dep.clone()).or_insert(0);
                        if *d > 0 { *d -= 1; }
                        if *d == 0 {
                            queue.push_back(dep.clone());
                        }
                    }
                }
                result.push(tx);
            }
        }

        for (_, tx) in tx_map {
            result.push(tx);
        }

        result
    }

    /// Compute Merkle root using the SAME MerkleTree implementation
    /// as block_validator.rs. MUST match exactly or blocks will be rejected.
    fn compute_merkle_root(coinbase: &Transaction, txs: &[Transaction], height: u64, parents: &[String]) -> String {
        use crate::domain::block::merkle_tree::MerkleTree;

        // Build full tx list in exact block body order: coinbase first, then txs
        let mut all_txs = Vec::with_capacity(1 + txs.len());
        all_txs.push(coinbase.clone());
        all_txs.extend_from_slice(txs);

        MerkleTree::build(&all_txs, height, parents)
    }
}
