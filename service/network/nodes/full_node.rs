// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;

use once_cell::sync::Lazy;

use crate::domain::block::block::Block;
use crate::domain::utxo::utxo_set::UtxoSet;

use crate::engine::consensus::validation::block_validator::BlockValidator;
use crate::config::node::node_config::NetworkMode;

use crate::engine::dag::core::dag_manager::DagManager;
use crate::engine::dag::ghostdag::ghostdag::{GhostDag, DagBlock};
use crate::engine::consensus::difficulty::retarget::{RetargetEngine, BlockTimeRecord, SHORT_WINDOW};

use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;
use crate::service::network::dos_guard::{DosGuard, DosVerdict, MsgType};
use crate::errors::{NodeError, ConsensusError};
use crate::{slog_info, slog_warn, slog_error};

// ═══════════════════════════════════════════════════════════════════════════
// Global next difficulty — written by FullNode after each block accepted,
// read by RPC getblocktemplate so miners always use the correct difficulty.
// ═══════════════════════════════════════════════════════════════════════════
static NEXT_DIFFICULTY: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(1));

/// Get the next expected difficulty for mining (called by RPC getblocktemplate).
pub fn get_next_difficulty() -> u64 {
    NEXT_DIFFICULTY.load(Ordering::Relaxed)
}

/// Update the next expected difficulty (called after each accepted block).
fn set_next_difficulty(diff: u64) {
    NEXT_DIFFICULTY.store(diff, Ordering::Relaxed);
}

// ═══════════════════════════════════════════════════════════════════════════
// Global DAG tips — written by FullNode after each block accepted,
// read by RPC getblocktemplate so miners reference correct parents.
// ═══════════════════════════════════════════════════════════════════════════
static DAG_TIPS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Get current DAG tips (blocks with no children) for mining.
pub fn get_dag_tips() -> Vec<String> {
    DAG_TIPS.lock().map(|t| t.clone()).unwrap_or_default()
}

/// Update the DAG tips (called after each accepted block).
fn set_dag_tips(tips: Vec<String>) {
    if let Ok(mut t) = DAG_TIPS.lock() {
        *t = tips;
    }
}

/// Maximum orphan blocks to hold in memory (DoS protection)
const MAX_ORPHAN_BLOCKS: usize = 500;

/// Maximum orphan blocks per peer (prevents single-peer flood)
const MAX_ORPHAN_PER_PEER: usize = 25;

/// Maximum age (seconds) before an orphan is evicted
const ORPHAN_EXPIRY_SECS: u64 = 600;

/// Maximum reorg depth: reject reorgs deeper than this to prevent
/// deep-reorg attacks. Blocks older than this are considered final.
const MAX_REORG_DEPTH: u64 = crate::engine::consensus::reorg::FINALITY_DEPTH;

/// Maximum blocks accepted per peer per minute (rate limiting)
const MAX_BLOCKS_PER_PEER_PER_MIN: usize = 60;

pub struct FullNode {
    pub block_store: Arc<BlockStore>,
    pub utxo_set: Arc<UtxoSet>,
    pub dag_manager: Arc<DagManager>,
    pub ghostdag: Arc<GhostDag>,
    pub network: NetworkMode,
    pub retarget: Mutex<RetargetEngine>,
    /// Orphan pool: blocks whose parents haven't arrived yet.
    /// Key: block hash, Value: (block, timestamp received).
    /// When a parent arrives, orphans are re-processed automatically.
    orphan_pool: Mutex<HashMap<String, (Block, u64, String)>>,  // block_hash → (block, timestamp, peer_id)
    /// Reverse index: parent_hash → vec of orphan block hashes waiting for it.
    orphan_by_parent: Mutex<HashMap<String, Vec<String>>>,
    /// Per-peer orphan count (DoS protection: ban peers flooding orphans)
    orphan_count_by_peer: Mutex<HashMap<String, usize>>,
    /// Per-peer block rate tracking: peer_id → vec of timestamps (last N minutes)
    peer_block_timestamps: Mutex<HashMap<String, Vec<u64>>>,
    /// Per-peer DoS guard: rate limits, bans, oversized message rejection
    dos_guard: DosGuard,
}

impl FullNode {
    pub fn new(
        block_store: Arc<BlockStore>,
        utxo_set: Arc<UtxoSet>,
        dag_manager: Arc<DagManager>,
        ghostdag: Arc<GhostDag>,
        network: NetworkMode,
    ) -> Self {
        // Start retarget with the genesis difficulty for this network,
        // NOT MIN_DIFFICULTY. This ensures the first blocks after genesis
        // are validated against a reasonable difficulty.
        let genesis_diff = crate::config::genesis::genesis::genesis_difficulty_for(&network);
        let mut retarget = RetargetEngine::new(genesis_diff);

        // ── Seed retarget from chain history ──────────────────────
        // On restart, load the last SHORT_WINDOW blocks from BlockStore
        // and replay them through the retarget engine. This recovers
        // the exact difficulty state without storing it separately.
        let blocks = block_store.get_all_blocks_sorted_by_height();
        let seed_count = blocks.len().min(SHORT_WINDOW);
        if seed_count > 1 {
            // Feed the last SHORT_WINDOW blocks (or all if fewer)
            let start_idx = blocks.len().saturating_sub(SHORT_WINDOW);
            for block in &blocks[start_idx..] {
                retarget.on_new_block(BlockTimeRecord {
                    height:          block.header.height,
                    timestamp:       block.header.timestamp,
                    difficulty:      block.header.difficulty,
                    dag_block_count: 1, // historical seed — no DAG width data
                });
            }
            let seeded_diff = retarget.ema_difficulty();
            set_next_difficulty(seeded_diff);
            slog_info!("node", "retarget_seeded", blocks => &seed_count.to_string(), ema_difficulty => &seeded_diff.to_string());
        } else {
            set_next_difficulty(genesis_diff);
        }

        // Initialize global DAG tips for getblocktemplate
        let initial_tips = dag_manager.get_tips();
        if !initial_tips.is_empty() {
            set_dag_tips(initial_tips);
        }

        Self {
            block_store,
            utxo_set,
            dag_manager,
            ghostdag,
            network,
            retarget: Mutex::new(retarget),
            orphan_pool: Mutex::new(HashMap::new()),
            orphan_by_parent: Mutex::new(HashMap::new()),
            orphan_count_by_peer: Mutex::new(HashMap::new()),
            peer_block_timestamps: Mutex::new(HashMap::new()),
            dos_guard: DosGuard::new(),
        }
    }

    /// Process a new block through the full consensus pipeline.
    ///
    /// Order: Validate → BlockStore → DAG → GHOSTDAG → UTXO → best_hash
    ///
    /// Crash safety:
    ///   - Crash after BlockStore: block saved, DAG/UTXO rebuilt by recovery
    ///   - Crash after DAG: block + topology saved, UTXO rebuilt by replay
    ///   - Crash during UTXO: WriteBatch + WAL = atomic (no partial state)
    ///   - Crash after UTXO: fully consistent
    ///
    /// Key invariant: BlockStore is ALWAYS written first (source of truth).
    /// Everything else can be rebuilt from BlockStore on recovery.
    /// Process a block received from a specific peer (with rate limiting).
    pub fn process_block_from_peer(&self, block: &Block, peer_id: &str) -> Result<(), NodeError> {
        // ── L0: Per-peer DoS guard (cheapest — no deserialization) ────
        let block_size = block.canonical_size_estimate();
        match self.dos_guard.check(peer_id, &MsgType::Block, block_size) {
            DosVerdict::Allow => {},
            DosVerdict::BanActive => {
                return Err(NodeError::PeerBanned { peer: peer_id.to_string(), reason: "peer is banned".to_string() });
            },
            verdict => {
                return Err(NodeError::PeerBanned { peer: peer_id.to_string(), reason: format!("DOS_REJECTED: {:?}", verdict) });
            },
        }

        // ── L0.5: Per-peer rate limiting ─────────────────────────────
        if self.is_peer_rate_limited(peer_id) {
            return Err(NodeError::PeerBanned { peer: peer_id.to_string(), reason: format!("RATE_LIMITED: exceeds {} blocks/min", MAX_BLOCKS_PER_PEER_PER_MIN) });
        }

        // ── L1 → L2 → L3 → DAG → L4 ────────────────────────────────
        self.process_block_inner(block, peer_id)
    }

    /// Process a block (internal use, no peer tracking).
    pub fn process_block(&self, block: &Block) -> Result<(), NodeError> {
        self.process_block_inner(block, "local")
    }

    /// Collect ancestor timestamps by walking the DAG deeply.
    ///
    /// Walks up to `TARGET_ANCESTOR_COUNT` ancestors via BFS to ensure the
    /// MTP window has enough data for a robust median calculation. Previous
    /// implementation only walked 2 levels (parents + grandparents), which
    /// gave ~4-8 timestamps — insufficient for the 11-block MTP window.
    ///
    /// **Important:** Does NOT dedup timestamps. Duplicate timestamps from
    /// parallel blocks at the same height are kept so the median correctly
    /// reflects the "weight" of blocks at that timestamp.
    fn collect_ancestor_timestamps(&self, block: &Block) -> Vec<u64> {
        use std::collections::{VecDeque, HashSet};

        const TARGET_ANCESTOR_COUNT: usize = 32; // Collect up to 32 ancestors
        const MAX_WALK_DEPTH: usize = 8;         // Walk up to 8 DAG levels

        let mut timestamps = Vec::with_capacity(TARGET_ANCESTOR_COUNT);
        let mut visited = HashSet::with_capacity(TARGET_ANCESTOR_COUNT);
        let mut queue: VecDeque<(String, usize)> = VecDeque::new(); // (hash, depth)

        // Seed with direct parents
        for parent_hash in &block.header.parents {
            if visited.insert(parent_hash.clone()) {
                queue.push_back((parent_hash.clone(), 1));
            }
        }

        // BFS walk up the DAG
        while let Some((hash, depth)) = queue.pop_front() {
            if timestamps.len() >= TARGET_ANCESTOR_COUNT {
                break;
            }

            if let Some(ancestor) = self.block_store.get_block(&hash) {
                timestamps.push(ancestor.header.timestamp);

                // Walk deeper if we haven't reached the depth limit
                if depth < MAX_WALK_DEPTH {
                    for gp_hash in &ancestor.header.parents {
                        if visited.insert(gp_hash.clone()) {
                            queue.push_back((gp_hash.clone(), depth + 1));
                        }
                    }
                }
            }
        }

        timestamps.sort_unstable();
        timestamps
    }

    fn process_block_inner(&self, block: &Block, peer_id: &str) -> Result<(), NodeError> {
        // ═══════════════════════════════════════════════════════════════
        // PHASE 1: STRUCTURAL VALIDATION (lock-free, fully parallel)
        //
        // Stateless checks — no UTXO dependency.
        // Invalid blocks rejected. Valid blocks accepted into DAG.
        // ═══════════════════════════════════════════════════════════════

        let expected_diff = {
            let retarget = self.retarget.lock()
                .map_err(|e| NodeError::Other(format!("Retarget lock poisoned: {}", e)))?;
            Some(retarget.ema_difficulty())
        };

        let ancestor_ts = self.collect_ancestor_timestamps(block);

        let result = BlockValidator::validate_block_full_with_difficulty(
            block, &self.utxo_set, &ancestor_ts, &self.network, expected_diff
        );
        if !result.valid {
            return Err(NodeError::BlockRejected(format!(
                "Block validation failed: {}",
                result.reason.unwrap_or_else(|| "unknown".to_string())
            )));
        }

        if self.dag_manager.block_exists(&block.header.hash) {
            return Err(NodeError::BlockRejected(format!("Block {} already exists in DAG", &block.header.hash)));
        }

        match BlockValidator::validate_parents_exist(block, &self.block_store, &self.dag_manager) {
            Ok(()) => {},
            Err(e) if e.to_string().contains("not found") => {
                self.add_orphan(block.clone(), peer_id);
                return Err(NodeError::BlockRejected(format!("ORPHAN: {}", e)));
            },
            Err(e) => return Err(NodeError::BlockRejected(format!("Parent validation failed: {}", e))),
        }

        // ═══════════════════════════════════════════════════════════════
        // PHASE 2: ACCEPT INTO DAG (no UTXO — structure only)
        //
        // A structurally valid block is ALWAYS accepted into the DAG.
        // NO UTXO execution here. UTXO is handled in Phase 3.
        // ═══════════════════════════════════════════════════════════════

        if !self.block_store.save_block(block) {
            return Err(NodeError::BlockRejected("Failed to save block to BlockStore".to_string()));
        }

        self.dag_manager.add_block_validated(block, true)
            .map_err(|e| NodeError::BlockRejected(format!("DAG insertion failed: {}", e)))?;

        let dag_block = DagBlock {
            hash: block.header.hash.clone(),
            parents: block.header.parents.clone(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        let _ghostdag_data = self.ghostdag.add_block(dag_block);

        // ═══════════════════════════════════════════════════════════════
        // PHASE 3: RECOMPUTE VIRTUAL CHAIN (GHOSTDAG-ordered execution)
        //
        // DAG PRINCIPLE: Execution follows GHOSTDAG ordering, NOT
        // arrival order. When a new block is added:
        //
        //   1. GHOSTDAG determines the new virtual selected parent chain
        //   2. Find where old chain and new chain diverge (split point)
        //   3. ROLLBACK blocks on old chain after split point
        //   4. APPLY blocks on new chain after split point
        //   5. Each block: skip conflicting txs, apply the rest
        //
        // This ensures that if Block B arrives before Block A, but
        // GHOSTDAG orders A before B, A's txs execute first.
        // ═══════════════════════════════════════════════════════════════
        self.recompute_virtual_chain()?;

        self.process_orphans_of(&block.header.hash);

        Ok(())
    }

    /// Same as process_block_inner but WITHOUT triggering orphan processing.
    /// Used by the iterative orphan resolver to avoid recursion.
    fn process_block_without_orphans(&self, block: &Block) -> Result<(), NodeError> {
        let expected_diff = {
            let retarget = self.retarget.lock()
                .map_err(|e| NodeError::Other(format!("Retarget lock poisoned: {}", e)))?;
            Some(retarget.ema_difficulty())
        };

        let ancestor_ts = self.collect_ancestor_timestamps(block);

        let result = BlockValidator::validate_block_full_with_difficulty(
            block, &self.utxo_set, &ancestor_ts, &self.network, expected_diff
        );
        if !result.valid {
            return Err(NodeError::BlockRejected(result.reason.unwrap_or_else(|| "unknown".to_string())));
        }

        if self.dag_manager.block_exists(&block.header.hash) {
            return Err(NodeError::BlockRejected("Already exists".to_string()));
        }

        BlockValidator::validate_parents_exist(block, &self.block_store, &self.dag_manager)
            .map_err(|e| NodeError::BlockRejected(e.to_string()))?;

        if !self.block_store.save_block(block) {
            return Err(NodeError::BlockRejected("Failed to save block".to_string()));
        }

        self.dag_manager.add_block_validated(block, true)
            .map_err(|e| NodeError::BlockRejected(format!("DAG insertion failed: {}", e)))?;

        let dag_block = DagBlock {
            hash: block.header.hash.clone(),
            parents: block.header.parents.clone(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        let _ghostdag_data = self.ghostdag.add_block(dag_block);

        self.recompute_virtual_chain()?;
        Ok(())
    }

    /// Recompute the virtual selected parent chain after DAG changes.
    ///
    /// Walks the GHOSTDAG ordering to determine which blocks should
    /// have their transactions executed, and in what order.
    ///
    /// If the selected chain changed (reorg), rolls back old blocks
    /// and applies new ones — all in GHOSTDAG order.
    pub fn recompute_virtual_chain(&self) -> Result<(), NodeError> {
        // Get the new best tip from GHOSTDAG
        let tips = self.ghostdag.get_tips();
        if tips.is_empty() { return Ok(()); }

        // Find tip with highest blue score
        let mut best_tip = tips[0].clone();
        let mut best_score = self.ghostdag.get_blue_score(&best_tip);

        for tip in &tips[1..] {
            let score = self.ghostdag.get_blue_score(tip);
            if score > best_score || (score == best_score && *tip < best_tip) {
                best_tip = tip.clone();
                best_score = score;
            }
        }

        let current_best = self.block_store.get_best_hash()
            .unwrap_or_default();

        if best_tip == current_best {
            return Ok(()); // No chain change
        }

        // Build the selected parent chain from new tip back to a common ancestor
        // with the old chain. For now, use a simplified approach:
        // walk new tip's selected parent chain until we find a block that
        // was already applied (exists in UTXO commitment store).
        let mut new_chain: Vec<String> = Vec::new();
        let mut cursor = best_tip.clone();

        loop {
            if self.utxo_set.get_commitment(&cursor).is_some() && cursor != best_tip {
                // This block was already applied — it's our split point
                break;
            }
            new_chain.push(cursor.clone());

            // Walk to selected parent
            match self.block_store.get_block(&cursor) {
                Some(b) => {
                    match b.header.selected_parent {
                        Some(ref sp) => cursor = sp.clone(),
                        None => break, // Genesis
                    }
                }
                None => break,
            }
        }

        // Reverse so we apply from oldest to newest (GHOSTDAG order)
        new_chain.reverse();

        // ── DEEP REORG PROTECTION ──────────────────────────────────────
        // Reject reorgs deeper than MAX_REORG_DEPTH. Blocks older than
        // this are considered final. This prevents an attacker from
        // secretly building a long side-chain and causing a massive reorg.
        if new_chain.len() as u64 > MAX_REORG_DEPTH {
            return Err(NodeError::BlockRejected(format!(
                "reorg depth {} exceeds MAX_REORG_DEPTH {}",
                new_chain.len(), MAX_REORG_DEPTH
            )));
        }

        // Rollback blocks that were on the old chain but not the new one
        // (simplified: rollback current_best if it's not in new_chain)
        if !current_best.is_empty() && !new_chain.contains(&current_best) {
            // Need to rollback the old tip
            let _ = self.utxo_set.rollback_block_undo(&current_best);
        }

        // Apply blocks in GHOSTDAG order (new chain)
        for block_hash in &new_chain {
            // Skip if already applied
            if self.utxo_set.get_commitment(block_hash).is_some() {
                continue;
            }

            if let Some(block) = self.block_store.get_block(block_hash) {
                match self.utxo_set.apply_block_dag_ordered(
                    &block.body.transactions,
                    block.header.height,
                    block_hash,
                ) {
                    Ok((_applied, _skipped, applied_fees)) => {
                        // POST-EXECUTION COINBASE VALIDATION
                        //
                        // Coinbase amounts can only be validated AFTER execution
                        // because applied_fees depend on which txs were skipped.
                        // This is the DEFINITIVE coinbase check.
                        use crate::config::consensus::emission_schedule::EmissionSchedule;
                        let expected_reward = EmissionSchedule::block_reward(block.header.height);
                        let expected_total = expected_reward.checked_add(applied_fees)
                    .ok_or_else(|| NodeError::Consensus(ConsensusError::BlockValidation("reward + fees overflow".into())))?;

                        if let Some(cb) = block.body.transactions.first() {
                            if cb.is_coinbase() {
                                let actual_total: u64 = match cb.outputs.iter()
                                    .try_fold(0u64, |acc, o| acc.checked_add(o.amount))
                                {
                                    Some(t) => t,
                                    None => {
                                        slog_error!("node", "coinbase_output_overflow", block => block_hash);
                                        let _ = self.utxo_set.rollback_block_undo(block_hash);
                                        continue;
                                    }
                                };
                                if actual_total != expected_total {
                                    slog_error!("node", "coinbase_mismatch", block => block_hash, actual => &actual_total.to_string(), expected => &expected_total.to_string());
                                    // Rollback this block's UTXO changes
                                    let _ = self.utxo_set.rollback_block_undo(block_hash);
                                    continue;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        slog_error!("node", "apply_block_dag_error", block => block_hash, error => &e.to_string());
                    }
                }
            }
        }

        // Update best hash
        self.block_store.update_best_hash(&best_tip);

        // Update retarget from selected chain and publish next difficulty
        if let Some(best_block) = self.block_store.get_block(&best_tip) {
            if let Ok(mut retarget) = self.retarget.lock() {
                // Count total DAG blocks at this height for DAG-aware difficulty.
                // This gives the retarget engine visibility into parallel blocks.
                let dag_width = (self.block_store.blocks_at_height(best_block.header.height) as u64).max(1);

                let next_diff = retarget.on_new_block(BlockTimeRecord {
                    height:          best_block.header.height,
                    timestamp:       best_block.header.timestamp,
                    difficulty:      best_block.header.difficulty,
                    dag_block_count: dag_width,
                });
                // Publish for RPC getblocktemplate
                set_next_difficulty(next_diff);
            }
        }

        // Update DAG tips for getblocktemplate — miners need current tips as parents
        let tips = self.dag_manager.get_tips();
        if !tips.is_empty() {
            set_dag_tips(tips);
        }

        // ── FINALITY: prune undo data for finalized blocks ────────────
        // Blocks deeper than FINALITY_DEPTH below the tip are irreversible.
        // Their undo data is no longer needed and wastes disk space.
        // At 10 BPS with 200-block depth, undo data is kept for ~20 seconds.
        {
            use crate::engine::consensus::reorg::FINALITY_DEPTH;
            if let Some(best_block) = self.block_store.get_block(&best_tip) {
                let tip_height = best_block.header.height;
                if tip_height > FINALITY_DEPTH {
                    let finality_height = tip_height - FINALITY_DEPTH;
                    // Collect block hashes at or below finality height
                    // that still have undo data (batch prune them)
                    let mut to_prune: Vec<String> = Vec::new();
                    for hash in &new_chain {
                        if let Some(b) = self.block_store.get_block(hash) {
                            if b.header.height <= finality_height
                                && self.utxo_set.has_undo_data(hash)
                            {
                                to_prune.push(hash.clone());
                            }
                        }
                    }
                    if !to_prune.is_empty() {
                        let pruned = self.utxo_set.prune_finalized_undo_data(&to_prune);
                        if pruned > 0 {
                            slog_info!("node", "pruned_undo_entries", count => &pruned.to_string(), finality_height => &finality_height.to_string());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════
    // ORPHAN POOL
    // ═══════════════════════════════════════════════════════════════════

    /// Add a block to the orphan pool (parent not yet known).
    /// peer_id identifies the sender for per-peer DoS protection.
    fn add_orphan(&self, block: Block, peer_id: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let block_hash = block.header.hash.clone();

        // DoS protection: evict expired orphans first
        self.evict_expired_orphans();

        // Per-peer orphan limit: prevent single peer from flooding
        if let Ok(counts) = self.orphan_count_by_peer.lock() {
            let peer_count = counts.get(peer_id).copied().unwrap_or(0);
            if peer_count >= MAX_ORPHAN_PER_PEER {
                slog_warn!("node", "orphan_per_peer_limit", peer => peer_id, limit => &MAX_ORPHAN_PER_PEER.to_string());
                return;
            }
        }

        let mut pool = match self.orphan_pool.lock() {
            Ok(p) => p,
            Err(_) => return,
        };

        // DoS protection: cap total orphans
        if pool.len() >= MAX_ORPHAN_BLOCKS {
            return;
        }

        // Don't re-add duplicates
        if pool.contains_key(&block_hash) {
            return;
        }

        // Register in reverse index: for each parent → this orphan
        if let Ok(mut by_parent) = self.orphan_by_parent.lock() {
            for parent_hash in &block.header.parents {
                by_parent.entry(parent_hash.clone())
                    .or_insert_with(Vec::new)
                    .push(block_hash.clone());
            }
        }

        // Track per-peer count
        if let Ok(mut counts) = self.orphan_count_by_peer.lock() {
            *counts.entry(peer_id.to_string()).or_insert(0) += 1;
        }

        pool.insert(block_hash, (block, now, peer_id.to_string()));
    }

    /// Check if a peer exceeds block rate limit (DoS protection).
    /// Returns true if the peer should be throttled.
    fn is_peer_rate_limited(&self, peer_id: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Ok(mut timestamps) = self.peer_block_timestamps.lock() {
            let entry = timestamps.entry(peer_id.to_string())
                .or_insert_with(Vec::new);

            // Remove timestamps older than 60 seconds
            entry.retain(|ts| now.saturating_sub(*ts) < 60);

            if entry.len() >= MAX_BLOCKS_PER_PEER_PER_MIN {
                return true; // Rate limited
            }

            entry.push(now);
        }

        false
    }

    /// After a block is accepted, check if any orphans were waiting for it.
    fn process_orphans_of(&self, parent_hash: &str) {
        // Iterative orphan resolution — avoids stack overflow from deep orphan chains.
        // Max depth prevents DoS via crafted chains of 500 orphans.
        const MAX_ORPHAN_DEPTH: usize = 64;

        let mut queue = vec![parent_hash.to_string()];
        let mut depth = 0;

        while let Some(current_parent) = queue.pop() {
            depth += 1;
            if depth > MAX_ORPHAN_DEPTH {
                slog_warn!("node", "orphan_chain_depth_exceeded", depth => &depth.to_string());
                break;
            }

            let waiting: Vec<String> = match self.orphan_by_parent.lock() {
                Ok(mut by_parent) => {
                    by_parent.remove(&current_parent).unwrap_or_default()
                }
                Err(_) => continue,
            };

            let mut blocks_to_process: Vec<Block> = Vec::new();
            if let Ok(mut pool) = self.orphan_pool.lock() {
                for hash in &waiting {
                    if let Some((block, _, _)) = pool.remove(hash) {
                        blocks_to_process.push(block);
                    }
                }
            }

            for block in blocks_to_process {
                let hash = block.header.hash.clone();
                if self.process_block_without_orphans(&block).is_ok() {
                    // This block was accepted — its children may now be ready
                    queue.push(hash);
                }
            }
        }
    }

    /// Evict orphans older than ORPHAN_EXPIRY_SECS (DoS protection).
    fn evict_expired_orphans(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut pool = match self.orphan_pool.lock() {
            Ok(p) => p,
            Err(_) => return,
        };

        let expired: Vec<String> = pool.iter()
            .filter(|(_, (_, ts, _))| now.saturating_sub(*ts) > ORPHAN_EXPIRY_SECS)
            .map(|(hash, _)| hash.clone())
            .collect();

        if expired.is_empty() { return; }

        // Clean up reverse index
        if let Ok(mut by_parent) = self.orphan_by_parent.lock() {
            for hash in &expired {
                if let Some((block, _, _)) = pool.get(hash) {
                    for parent_hash in &block.header.parents {
                        if let Some(list) = by_parent.get_mut(parent_hash) {
                            list.retain(|h| h != hash);
                            if list.is_empty() {
                                by_parent.remove(parent_hash);
                            }
                        }
                    }
                }
            }
        }

        // Decrement per-peer counts for evicted orphans
        if let Ok(mut counts) = self.orphan_count_by_peer.lock() {
            for hash in &expired {
                if let Some((_, _, peer_id)) = pool.get(hash) {
                    if let Some(c) = counts.get_mut(peer_id) {
                        *c = c.saturating_sub(1);
                        if *c == 0 { counts.remove(peer_id); }
                    }
                }
            }
        }

        for hash in expired {
            pool.remove(&hash);
        }
    }

    /// Process genesis block — same pipeline minus parent validation.
    pub fn process_genesis(&self, block: &Block) -> Result<(), NodeError> {

        // ═══════════════════════════════════════════════════════════════
        // PHASE 1: VALIDATE (read-only — NO state changes)
        // ═══════════════════════════════════════════════════════════════

        // 1a: Structural validation (PoW, coinbase, etc.)
        let result = BlockValidator::validate_block_full_with_network(block, &self.utxo_set, &self.network);
        if !result.valid {
            return Err(NodeError::BlockRejected(format!(
                "Genesis validation failed: {}",
                result.reason.unwrap_or_else(|| "unknown".to_string())
            )));
        }
        // Skip parent validation — genesis has no parents by definition

        // 1b: UTXO validation BEFORE any writes (genesis coinbase only)
        use crate::domain::utxo::utxo_validator::UtxoValidator;
        UtxoValidator::validate_block_utxos(block, &self.utxo_set, 0)
            .map_err(|e| NodeError::BlockRejected(format!("Genesis UTXO validation failed: {}", e)))?;

        // ═══════════════════════════════════════════════════════════════
        // PHASE 2: COMMIT (block is fully validated)
        // ═══════════════════════════════════════════════════════════════

        // Save block
        if !self.block_store.save_block(block) {
            return Err(NodeError::BlockRejected("Failed to save genesis to BlockStore".to_string()));
        }

        // DAG insertion — genesis MUST succeed, otherwise the node starts
        // with an inconsistent state from the very first block.
        self.dag_manager.add_block_validated(block, true)
            .map_err(|e| NodeError::BlockRejected(format!("Genesis DAG insertion failed (fatal): {}", e)))?;

        // GHOSTDAG ordering
        let dag_block = DagBlock {
            hash: block.header.hash.clone(),
            parents: block.header.parents.clone(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        let _ghostdag_data = self.ghostdag.add_block(dag_block);

        // UTXO write + commitment ATOMICALLY (validation already passed in Phase 1)
        let _commitment = self.utxo_set.apply_block_write_with_commitment(
            &block.body.transactions, 0, &block.header.hash
        ).map_err(|e| NodeError::BlockRejected(format!("Genesis UTXO write failed: {}", e)))?;

        // Genesis is always best
        self.block_store.update_best_hash(&block.header.hash);

        Ok(())
    }

    pub fn get_tips(&self) -> Vec<String> {
        self.ghostdag.get_tips()
    }

}

impl crate::domain::traits::block_processor::BlockProcessor for FullNode {
    fn process_block(&self, block: &crate::domain::block::block::Block) -> Result<(), NodeError> {
        self.process_block(block)
    }

    fn get_tips(&self) -> Vec<String> {
        self.get_tips()
    }
}
