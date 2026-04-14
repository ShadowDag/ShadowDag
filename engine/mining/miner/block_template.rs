// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::consensus::consensus_params::ConsensusParams;
use crate::config::consensus::emission_schedule::EmissionSchedule;
use crate::domain::block::block::Block;
use crate::domain::block::block_body::BlockBody;
use crate::domain::block::block_header::BlockHeader;
use crate::domain::traits::tx_pool::TxPool;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::transaction::tx_builder::build_coinbase_at_height;
use crate::domain::transaction::tx_validator::TxValidator;
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_set::{utxo_key, UtxoSet};
use crate::engine::dag::core::dag_manager::DagManager;
use crate::engine::dag::security::dos_protection::{MAX_BLOCK_TX_COUNT, MAX_DAG_PARENTS};
use crate::engine::dag::tips::tip_manager::TipManager;
use crate::errors::ConsensusError;
use crate::slog_warn;
use std::collections::{HashMap, HashSet, VecDeque};

pub struct BlockTemplateBuilder;

pub struct BlockTemplate {
    pub transactions: Vec<Transaction>,
    pub total_fees: u64,
    pub tx_count: usize,
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
            return Err(ConsensusError::Other(
                "No DAG tips available for parent selection".to_string(),
            ));
        }

        // Validate all parent blocks exist in the DAG
        let mut validated_parents: Vec<String> = Vec::with_capacity(candidates.len());
        for parent_hash in &candidates {
            if !dag_manager.block_exists(parent_hash) {
                slog_warn!("mining", "tip_not_found_in_dag", hash_prefix => &parent_hash[..parent_hash.len().min(16)]);
                continue;
            }
            validated_parents.push(parent_hash.clone());
        }

        if validated_parents.is_empty() {
            return Err(ConsensusError::Other(
                "No valid parent blocks found in DAG".to_string(),
            ));
        }

        // Sort parents lexicographically — consensus requires
        // deterministic parent ordering so all nodes agree.
        validated_parents.sort();
        Ok(validated_parents)
    }

    /// Build a block template using current DAG tips as parents.
    /// This is the primary entry point that properly connects mining to the DAG.
    pub fn build_from_dag(
        tip_manager: &TipManager,
        dag_manager: &DagManager,
        mempool: &dyn TxPool,
        utxo_set: &UtxoSet,
        miner_address: &str,
        timestamp: u64,
        difficulty: u64,
    ) -> Result<Block, ConsensusError> {
        let parents = Self::select_dag_parents(tip_manager, dag_manager)?;

        // Read tips ONCE to avoid TOCTOU between height, selected_parent,
        // and blue_score computations. If tips change between reads, the
        // template could have an inconsistent combination.
        let tips = tip_manager.get_tips();
        let tip_map_height: std::collections::HashMap<&str, u64> =
            tips.iter().map(|t| (t.hash.as_str(), t.height)).collect();
        let tip_map_score: std::collections::HashMap<&str, u64> = tips
            .iter()
            .map(|t| (t.hash.as_str(), t.blue_score))
            .collect();

        // Height MUST be max(parent_heights) + 1 (consensus rule).
        // Using tip_manager.best_height() can produce incorrect
        // heights when DAG tips lag behind the actual max parent.
        let height = {
            let mut max_parent_height = 0u64;
            for parent_hash in &parents {
                if let Some(&ph) = tip_map_height.get(parent_hash.as_str()) {
                    max_parent_height = max_parent_height.max(ph);
                }
            }
            max_parent_height + 1
        };

        // Pull transactions from mempool, validate against current UTXO state
        // NOTE: must select transactions BEFORE building coinbase so we know total fees.
        let candidates = mempool.get_transactions_for_block(
            utxo_set,
            MAX_BLOCK_TX_COUNT - 1, // reserve slot for coinbase
        );

        let template = Self::select_valid_transactions(candidates, utxo_set);

        // Coinbase reward = emission + transaction fees (must match validator expectation)
        let emission = EmissionSchedule::block_reward(height);
        let reward = emission.checked_add(template.total_fees).ok_or_else(|| {
            ConsensusError::Other("coinbase reward overflow: emission + fees exceeds u64".into())
        })?;

        let coinbase = build_coinbase_at_height(
            miner_address.to_string(),
            ConsensusParams::OWNER_REWARD_ADDRESS.to_string(),
            reward,
            ConsensusParams::MINER_PERCENT,
            timestamp,
            height,
        );

        let merkle_root =
            Self::compute_merkle_root(&coinbase, &template.transactions, height, &parents);

        // Selected parent = parent with highest blue score, NOT the
        // lexicographically first. The parent list is sorted lexicographically
        // for consensus determinism, but the selected parent follows GHOSTDAG
        // ordering (highest blue score wins, then lexicographic tiebreaker).
        // Uses tip_map_score from the single tips read above (no re-read).
        let selected_parent = {
            let best = parents
                .iter()
                .max_by(|a, b| {
                    let sa = tip_map_score.get(a.as_str()).copied().unwrap_or(0);
                    let sb = tip_map_score.get(b.as_str()).copied().unwrap_or(0);
                    sa.cmp(&sb).then_with(|| b.cmp(a)) // higher score, then lower hash
                })
                .cloned();
            // Warn if the best parent has score 0 (not found in tips) —
            // this means the selected_parent choice is based on fallback
            // ordering, not GHOSTDAG blue score.
            if let Some(ref best_hash) = best {
                if tip_map_score.get(best_hash.as_str()).copied().unwrap_or(0) == 0 {
                    slog_warn!("mining", "selected_parent_not_in_tips",
                        parent => &best_hash[..best_hash.len().min(16)],
                        note => "parent not found in tip_manager — using fallback ordering");
                }
            }
            best.or_else(|| parents.first().cloned())
        };

        // APPROXIMATION: blue_score = max(parent_blue_scores) + 1.
        // The real GHOSTDAG blue score is computed when the block is
        // inserted into GHOSTDAG (ghostdag.add_block). This template
        // value is a best-effort estimate that may differ from the
        // GHOSTDAG result. Since blue_score in the header is overwritten
        // by GHOSTDAG on insertion, this approximation only affects
        // pre-insertion display (e.g., getblocktemplate RPC response).
        // If blue_score accuracy matters before insertion, query
        // GHOSTDAG directly.
        // Uses tip_map_score from the single tips read above (no re-read).
        let blue_score = {
            parents
                .iter()
                .filter_map(|p| tip_map_score.get(p.as_str()))
                .max()
                .copied()
                .unwrap_or(0)
                .saturating_add(1)
        };

        let header = BlockHeader {
            version: 1,
            hash: String::new(),
            parents,
            merkle_root,
            timestamp,
            nonce: 0,
            difficulty,
            height,
            blue_score,
            selected_parent,
            utxo_commitment: None,
            extra_nonce: 0,
            receipt_root: None,
            state_root: None,
        };

        let mut all_txs = vec![coinbase];
        all_txs.extend(template.transactions);

        Ok(Block {
            header,
            body: BlockBody {
                transactions: all_txs,
            },
        })
    }

    /// Legacy build method — accepts explicit parents (kept for backward compatibility).
    #[allow(clippy::too_many_arguments)]
    /// DEPRECATED: Use `build_from_dag()` instead. This legacy method sets
    /// `blue_score = 0` and `selected_parent = parents.first()` without
    /// GHOSTDAG input, producing headers with incorrect DAG metadata.
    #[deprecated(note = "Use build_from_dag() for correct DAG-aware template building")]
    pub fn build(
        mempool: &dyn TxPool,
        utxo_set: &UtxoSet,
        miner_address: &str,
        height: u64,
        timestamp: u64,
        parents: Vec<String>,
        difficulty: u64,
        _prev_hash: &str,
    ) -> Block {
        // Select transactions BEFORE building coinbase so we know total fees
        let candidates = mempool.get_transactions_for_block(utxo_set, MAX_BLOCK_TX_COUNT - 1);

        let template = Self::select_valid_transactions(candidates, utxo_set);

        // Coinbase reward = emission + transaction fees.
        // Legacy method returns Block (not Result), so avoid panics here.
        // Production path is build_from_dag() which returns Result and should
        // be preferred by callers.
        let emission = EmissionSchedule::block_reward(height);
        let reward = emission.saturating_add(template.total_fees);
        if reward == u64::MAX && emission != u64::MAX && template.total_fees != 0 {
            slog_warn!("mining", "legacy_coinbase_reward_saturated",
                height => height,
                emission => emission,
                total_fees => template.total_fees);
        }

        let coinbase = build_coinbase_at_height(
            miner_address.to_string(),
            ConsensusParams::OWNER_REWARD_ADDRESS.to_string(),
            reward,
            ConsensusParams::MINER_PERCENT,
            timestamp,
            height,
        );

        let merkle_root =
            Self::compute_merkle_root(&coinbase, &template.transactions, height, &parents);

        let selected_parent = parents.first().cloned();

        let header = BlockHeader {
            version: 1,
            hash: String::new(),
            parents,
            merkle_root,
            timestamp,
            nonce: 0,
            difficulty,
            height,
            blue_score: 0,
            selected_parent,
            utxo_commitment: None,
            extra_nonce: 0,
            receipt_root: None,
            state_root: None,
        };

        let mut all_txs = vec![coinbase];
        all_txs.extend(template.transactions);

        Block {
            header,
            body: BlockBody {
                transactions: all_txs,
            },
        }
    }

    fn select_valid_transactions(
        candidates: Vec<Transaction>,
        utxo_set: &UtxoSet,
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
                    Err(_) => {
                        bad_key = true;
                        break;
                    }
                }
            }
            if bad_key || conflict {
                continue;
            }

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
                    Err(_) => {
                        utxo_ok = false;
                        break;
                    }
                }
            }
            if !utxo_ok {
                continue;
            }

            if !tx.is_coinbase() && !TxValidator::validate_tx(&tx, utxo_set) {
                // TX failed full validation — reject it regardless of staged UTXO status.
                // Previously, TXs whose inputs were all in staged_utxos were accepted
                // even when signature/fee/ring checks failed. This bypassed consensus.
                //
                // KNOWN LIMITATION: validate_tx runs against the base UTXO set only,
                // not against (base + staged_utxos). This means a child TX whose
                // parent was included earlier in THIS block will fail UTXO-existence
                // checks even though the UTXO will exist when the block is executed.
                // The UTXO-existence pre-check above (in_real || in_staged) catches
                // the common case, but signature verification for inputs that reference
                // intra-block outputs may still fail if the validator's UTXO lookup
                // is needed for amount/script checks. A full fix requires passing a
                // merged UtxoSet view (base + staged) to validate_tx, which is
                // deferred to avoid changing the TxValidator interface mid-release.
                continue;
            }

            let mut skip = false;
            for input in &tx.inputs {
                match utxo_key(&input.txid, input.index) {
                    Ok(key) => {
                        spent_in_block.insert(key);
                    }
                    Err(_) => {
                        skip = true;
                        break;
                    }
                }
            }
            if skip {
                continue;
            }

            for (idx, output) in tx.outputs.iter().enumerate() {
                match utxo_key(&tx.hash, idx as u32) {
                    Ok(key) => {
                        staged_utxos.insert(key, (output.address.clone(), output.amount));
                    }
                    Err(_) => {
                        skip = true;
                        break;
                    }
                }
            }
            if skip {
                continue;
            }

            // BUG FIX: Use saturating_add to prevent overflow panic.
            // If a malicious mempool TX has fee near u64::MAX, a simple
            // += would wrap/panic in debug builds. Saturating keeps the
            // total capped at u64::MAX which is safe for the coinbase
            // reward calculation (emission.saturating_add(total_fees)).
            total_fees = total_fees.saturating_add(tx.fee);
            accepted.push(tx);
        }

        BlockTemplate {
            tx_count: accepted.len(),
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
                    edges
                        .entry(input.txid.clone())
                        .or_default()
                        .push(tx.hash.clone());
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
                        if *d > 0 {
                            *d -= 1;
                        }
                        if *d == 0 {
                            queue.push_back(dep.clone());
                        }
                    }
                }
                result.push(tx);
            }
        }

        // Remaining TXs in tx_map have unresolved dependencies (cycles or missing
        // parents within the batch). Drop them rather than appending unsorted,
        // which would violate topological ordering guarantees.
        if !tx_map.is_empty() {
            slog_warn!("mining", "topological_sort_dropped_txs", count => tx_map.len());
        }

        result
    }

    /// Compute Merkle root using the SAME MerkleTree implementation
    /// as block_validator.rs. MUST match exactly or blocks will be rejected.
    fn compute_merkle_root(
        coinbase: &Transaction,
        txs: &[Transaction],
        height: u64,
        parents: &[String],
    ) -> String {
        use crate::domain::block::merkle_tree::MerkleTree;

        // Build full tx list in exact block body order: coinbase first, then txs
        let mut all_txs = Vec::with_capacity(1 + txs.len());
        all_txs.push(coinbase.clone());
        all_txs.extend_from_slice(txs);

        MerkleTree::build(&all_txs, height, parents)
    }
}
