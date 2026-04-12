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
use crate::domain::transaction::transaction::TxType;
use crate::domain::transaction::tx_receipt::{TxReceipt, ReceiptStore, compute_receipt_root};
use crate::runtime::vm::core::vm::ExecutionResult;
use crate::runtime::vm::core::execution_env::{ExecutionEnvironment, BlockContext, CallContext, CallOutcome};
use crate::runtime::vm::contracts::contract_storage::ContractStorage;
use crate::{slog_info, slog_warn, slog_error};

// ═══════════════════════════════════════════════════════════════════════════
// Mining template state — per-node, not per-process
// ═══════════════════════════════════════════════════════════════════════════
//
// The previous implementation stored `NEXT_DIFFICULTY` and `DAG_TIPS`
// as `static Lazy<…>` globals on the process. That works for a single
// FullNode per process, but leaks state between instances whenever a
// test (or a future multi-tenant deployment) spins up more than one
// node: both nodes share the same `NEXT_DIFFICULTY` / `DAG_TIPS`, so
// one node's retarget leaks into the other's `getblocktemplate`
// response and mining payloads synthesized for node A can reference
// node B's parent tips. That was marked as a P2 issue in the audit
// ("global at process level; cross-instance contamination") and is
// fixed by moving the state into a per-FullNode `MiningTemplateState`
// that is also exposed on `RpcState` via `Arc` so RPC endpoints can
// read and write the same cells.
//
// The legacy free functions `get_next_difficulty` /
// `get_dag_tips` / `set_next_difficulty` / `set_dag_tips` are
// retained as thin delegates to a process-default fallback so any
// external caller that used them keeps working, but the hot paths
// inside `FullNode` and the RPC contract handlers now route through
// the per-instance `Arc<MiningTemplateState>`.

/// Per-instance mining template cache.
///
/// Both `FullNode` and `RpcState` hold an `Arc<MiningTemplateState>`
/// pointing at the same cell, so a retarget commit on the node
/// becomes visible to the RPC `getblocktemplate` handler without
/// going through a process-global. Tests that spin up multiple
/// nodes in one process each get their own cell, so one node's
/// state can no longer leak into another's mining payloads.
pub struct MiningTemplateState {
    next_difficulty: AtomicU64,
    dag_tips:        Mutex<Vec<String>>,
}

impl MiningTemplateState {
    pub fn new() -> Self {
        Self {
            next_difficulty: AtomicU64::new(1),
            dag_tips:        Mutex::new(Vec::new()),
        }
    }

    pub fn next_difficulty(&self) -> u64 {
        self.next_difficulty.load(Ordering::Relaxed)
    }

    pub fn set_next_difficulty(&self, diff: u64) {
        self.next_difficulty.store(diff, Ordering::Relaxed);
    }

    pub fn dag_tips(&self) -> Vec<String> {
        self.dag_tips
            .lock()
            .map(|t| t.clone())
            .unwrap_or_default()
    }

    pub fn set_dag_tips(&self, tips: Vec<String>) {
        if let Ok(mut t) = self.dag_tips.lock() {
            *t = tips;
        }
    }
}

impl Default for MiningTemplateState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Legacy process-default ────────────────────────────────────────
//
// Retained for any caller that still uses the free functions and
// hasn't been plumbed an explicit `Arc<MiningTemplateState>` yet.
// The FullNode::new path stamps its own `Arc` into this slot on
// first creation so the RPC free-function readers still observe
// the active node's cell.
static PROCESS_DEFAULT_MINING_STATE: Lazy<MiningTemplateState> =
    Lazy::new(MiningTemplateState::new);

/// Get the next expected difficulty for mining from the
/// process-default cell. Prefer reading
/// `RpcState::mining_state.next_difficulty()` directly.
pub fn get_next_difficulty() -> u64 {
    PROCESS_DEFAULT_MINING_STATE.next_difficulty()
}

fn set_next_difficulty(diff: u64) {
    PROCESS_DEFAULT_MINING_STATE.set_next_difficulty(diff)
}

/// Get the DAG tips from the process-default cell. Prefer reading
/// `RpcState::mining_state.dag_tips()` directly.
pub fn get_dag_tips() -> Vec<String> {
    PROCESS_DEFAULT_MINING_STATE.dag_tips()
}

fn set_dag_tips(tips: Vec<String>) {
    PROCESS_DEFAULT_MINING_STATE.set_dag_tips(tips)
}

/// Reset the process-default mining template cell. Test-only.
#[cfg(test)]
pub fn reset_mining_globals() {
    PROCESS_DEFAULT_MINING_STATE.set_next_difficulty(0);
    PROCESS_DEFAULT_MINING_STATE.set_dag_tips(Vec::new());
}

/// Maximum orphan blocks to hold in memory (DoS protection)
const MAX_ORPHAN_BLOCKS: usize = 500;

/// Maximum orphan blocks per peer (prevents single-peer flood)
const MAX_ORPHAN_PER_PEER: usize = 25;

/// Maximum age (seconds) before an orphan is evicted.
/// Tightened from 600s to 120s to reduce the selfish mining withholding
/// window. At 10 BPS, 120s = 1200 blocks (vs previous 6000 blocks).
const ORPHAN_EXPIRY_SECS: u64 = 120;

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
    /// Persistent contract state DB (opened from ~/.shadowdag/<network>/contracts/)
    pub contract_storage: Arc<ContractStorage>,
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
    /// Receipt store for contract execution receipts
    pub receipt_store: ReceiptStore,
    /// Per-instance mining template cache. Shared with `RpcState`
    /// so `getblocktemplate` / `getwork` on the RPC side reads the
    /// same `next_difficulty` / `dag_tips` cells this node writes
    /// to after each accepted block — without going through a
    /// process-global that would leak between co-tenant nodes.
    pub mining_state: Arc<MiningTemplateState>,
}

impl FullNode {
    pub fn new(
        block_store: Arc<BlockStore>,
        utxo_set: Arc<UtxoSet>,
        dag_manager: Arc<DagManager>,
        ghostdag: Arc<GhostDag>,
        network: NetworkMode,
        contract_storage: Arc<ContractStorage>,
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
                    blue_score:      block.header.blue_score,
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
            set_dag_tips(initial_tips.clone());
        }

        // ── Startup recovery: verify contract state_root ──────────
        if let Some(best_hash) = block_store.get_best_hash() {
            if let Some(best_block) = block_store.get_block(&best_hash) {
                if let Some(ref expected_root) = best_block.header.state_root {
                    slog_info!("node", "contract_state_check",
                        expected => expected_root,
                        note => "full state verification requires replay from last checkpoint");
                }
            }
        }

        // Build the per-instance mining template cell. We seed
        // both it and the process-default cell so any legacy
        // caller that still uses the `get_next_difficulty` /
        // `get_dag_tips` free functions sees the same values.
        let mining_state = Arc::new(MiningTemplateState::new());
        mining_state.set_next_difficulty(
            if seed_count > 1 { retarget.ema_difficulty() } else { genesis_diff }
        );
        if !initial_tips.is_empty() {
            mining_state.set_dag_tips(initial_tips.clone());
        }

        Self {
            block_store,
            utxo_set,
            dag_manager,
            ghostdag,
            network,
            contract_storage,
            retarget: Mutex::new(retarget),
            orphan_pool: Mutex::new(HashMap::new()),
            orphan_by_parent: Mutex::new(HashMap::new()),
            orphan_count_by_peer: Mutex::new(HashMap::new()),
            peer_block_timestamps: Mutex::new(HashMap::new()),
            dos_guard: DosGuard::new(),
            receipt_store: ReceiptStore::new(100_000),
            mining_state,
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

        // ── L0.25: Exact serialized size check ────────────────────────
        // DosGuard::check uses canonical_size_estimate which under-counts;
        // this uses the real DoS guard size limit for a hard reject.
        if let Err(e) = self.dos_guard.check_block_size(block_size) {
            return Err(NodeError::PeerBanned {
                peer: peer_id.to_string(),
                reason: format!("BLOCK_TOO_LARGE: {}", e),
            });
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
        const MAX_WALK_DEPTH: usize = 16;        // Walk up to 16 DAG levels (>= MEDIAN_TIME_SPAN=11 + headroom for DAG branching)

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
        // CONSENSUS-CRITICAL VALIDATION PIPELINE
        //
        // Three strictly-separated phases. Ordering is a SAFETY INVARIANT:
        //
        //   Phase 1 (STATELESS): L1→PoW→L2→L3 — NO DB/UTXO reads.
        //     Inputs:  block header + body only (+ pre-collected ancestor timestamps)
        //     Checks:  format, size, signatures, merkle root, PoW, difficulty
        //     Merkle tree uses rayon par_iter — SAFE because deterministic
        //     (same TX order → same hash, regardless of thread scheduling)
        //
        //   Phase 2 (DAG): Parent existence + DAG insertion — reads block_store
        //     Only reached if Phase 1 passes. No UTXO changes.
        //
        //   Phase 3 (UTXO EXECUTION): Apply transactions in GHOSTDAG order
        //     Only reached after Phase 2. Reads/writes UTXO set.
        //     Sequential, single-threaded, atomic rollback on failure.
        //
        // INVARIANT: Phase 1 MUST NOT read from block_store, utxo_set,
        //            dag_manager, or any mutable state. Violation = consensus
        //            bug where nodes disagree on block validity.
        // ═══════════════════════════════════════════════════════════════

        // NOTE: ema_difficulty() returns the tip-chain's difficulty
        // estimate. For side-chain blocks this may differ from the
        // difficulty their parents imply, but ShadowDAG's GHOSTDAG
        // reorg mechanism re-validates after insertion, so a block
        // accepted on this path will be re-checked when (if) it
        // becomes part of the selected chain. A per-parent-context
        // retarget would be more precise but requires walking the
        // parent chain for every incoming block — acceptable for now.
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

        // ─── PHASE 1 END ─── (above: stateless only, no DB reads) ───

        // ─── PHASE 2 START ─── (stateful: reads block_store, dag_manager) ───
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
        // PHASE 2: PERSIST THEN ACCEPT INTO DAG (no UTXO — structure only)
        //
        // BlockStore is the source of truth. Persist FIRST so that if
        // the node crashes after save but before DAG insertion, recovery
        // can rebuild the DAG from BlockStore. If save fails, we must
        // NOT insert into the DAG (no topology without data).
        // ═══════════════════════════════════════════════════════════════

        if !self.block_store.save_block(block) {
            return Err(NodeError::BlockRejected(format!(
                "BlockStore save failed for {} — refusing to add to DAG without persistence",
                &block.header.hash
            )));
        }

        if let Err(e) = self.dag_manager.add_block_validated(block, true) {
            // Clean up persisted block — DAG rejected it, so it must not remain in BlockStore
            let _ = self.block_store.delete_block(&block.header.hash);
            return Err(NodeError::BlockRejected(format!("DAG insertion failed: {}", e)));
        }

        let dag_block = DagBlock {
            hash: block.header.hash.clone(),
            parents: block.header.parents.clone(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        if let Err(e) = self.ghostdag.add_block(dag_block) {
            // Cleanup: remove from BlockStore since GHOSTDAG rejected
            let _ = self.block_store.delete_block(&block.header.hash);
            // Note: DAG manager doesn't support remove, so log the inconsistency
            slog_error!("node", "ghostdag_add_failed_cleanup",
                hash => &block.header.hash, error => &e.to_string(),
                note => "block removed from BlockStore; DAG entry may be stale until reindex");
            return Err(NodeError::BlockRejected(format!("GHOSTDAG: {}", e)));
        }

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
        if let Err(e) = self.recompute_virtual_chain() {
            // Best-effort cleanup: DAG/GHOSTDAG don't support remove, but
            // we can at least remove the block from BlockStore to prevent
            // the inconsistency from persisting across restarts.
            let _ = self.block_store.delete_block(&block.header.hash);
            slog_error!("node", "virtual_chain_recompute_failed_after_insert",
                hash => &block.header.hash, error => &e.to_string());
            return Err(e);
        }

        self.process_orphans_of(&block.header.hash);

        Ok(())
    }

    /// Same as process_block_inner but WITHOUT triggering orphan processing.
    /// Used by the iterative orphan resolver to avoid recursion.
    fn process_block_without_orphans(&self, block: &Block) -> Result<(), NodeError> {
        // NOTE: ema_difficulty() returns the tip-chain's difficulty
        // estimate. For side-chain blocks this may differ from the
        // difficulty their parents imply, but ShadowDAG's GHOSTDAG
        // reorg mechanism re-validates after insertion, so a block
        // accepted on this path will be re-checked when (if) it
        // becomes part of the selected chain. A per-parent-context
        // retarget would be more precise but requires walking the
        // parent chain for every incoming block — acceptable for now.
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
            return Err(NodeError::BlockRejected(format!(
                "BlockStore save failed for {} — refusing to add to DAG without persistence",
                &block.header.hash
            )));
        }

        if let Err(e) = self.dag_manager.add_block_validated(block, true) {
            // Clean up persisted block — DAG rejected it, so it must not remain in BlockStore
            let _ = self.block_store.delete_block(&block.header.hash);
            return Err(NodeError::BlockRejected(format!("DAG insertion failed: {}", e)));
        }

        let dag_block = DagBlock {
            hash: block.header.hash.clone(),
            parents: block.header.parents.clone(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        if let Err(e) = self.ghostdag.add_block(dag_block) {
            // Cleanup: remove from BlockStore since GHOSTDAG rejected
            let _ = self.block_store.delete_block(&block.header.hash);
            // Note: DAG manager doesn't support remove, so log the inconsistency
            slog_error!("node", "ghostdag_add_failed_cleanup",
                hash => &block.header.hash, error => &e.to_string(),
                note => "block removed from BlockStore; DAG entry may be stale until reindex");
            return Err(NodeError::BlockRejected(format!("GHOSTDAG: {}", e)));
        }

        if let Err(e) = self.recompute_virtual_chain() {
            // Best-effort cleanup: DAG/GHOSTDAG don't support remove, but
            // we can at least remove the block from BlockStore to prevent
            // the inconsistency from persisting across restarts.
            let _ = self.block_store.delete_block(&block.header.hash);
            slog_error!("node", "virtual_chain_recompute_failed_after_insert",
                hash => &block.header.hash, error => &e.to_string());
            return Err(e);
        }
        Ok(())
    }

    /// Select the best tip from a set of DAG tips using the canonical rule:
    ///   highest blue_score -> highest chain_height -> lowest hash (deterministic)
    ///
    /// This MUST be used everywhere a "best tip" is chosen (runtime AND recovery)
    /// to guarantee consistent fork-choice across restarts.
    pub fn select_best_tip(tips: &[String], ghostdag: &GhostDag) -> Option<String> {
        tips.iter()
            .max_by(|a, b| {
                ghostdag.get_blue_score(a).cmp(&ghostdag.get_blue_score(b))
                    .then_with(|| ghostdag.get_chain_height(a).cmp(&ghostdag.get_chain_height(b)))
                    .then_with(|| b.cmp(a)) // lower hash wins
            })
            .cloned()
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

        // Use canonical tip selection: blue_score -> height -> hash
        let best_tip = match Self::select_best_tip(&tips, &self.ghostdag) {
            Some(tip) => tip,
            None => return Ok(()),
        };

        let current_best = self.block_store.get_best_hash()
            .unwrap_or_default();

        if best_tip == current_best {
            return Ok(()); // No chain change
        }

        // Build the selected parent chain from new tip back to the true fork
        // point with the old chain. Walk both chains (new tip and current best)
        // back via selected_parent to find where they diverge.
        use std::collections::HashSet;

        // First, collect the old chain's selected-parent ancestry
        let mut old_chain_set = HashSet::new();
        {
            let mut cursor = current_best.clone();
            while !cursor.is_empty() {
                old_chain_set.insert(cursor.clone());
                cursor = self.block_store.get_block(&cursor)
                    .and_then(|b| b.header.selected_parent.clone())
                    .unwrap_or_default();
            }
        }

        // Walk the new tip's selected-parent chain until we hit a block
        // that exists in the old chain (the true fork point).
        let mut new_chain: Vec<String> = Vec::new();
        let mut cursor = best_tip.clone();

        loop {
            if old_chain_set.contains(&cursor) && cursor != best_tip {
                // This block is on the old chain — it's our fork point
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
        if new_chain.len() as u64 >= MAX_REORG_DEPTH {
            return Err(NodeError::BlockRejected(format!(
                "reorg depth {} exceeds MAX_REORG_DEPTH {}",
                new_chain.len(), MAX_REORG_DEPTH
            )));
        }

        // Rollback entire old chain from current_best back to fork point
        let mut rolled_back_old: Vec<String> = Vec::new();
        if !current_best.is_empty() && !new_chain.contains(&current_best) {
            let mut cursor = current_best.clone();
            let mut rollback_count = 0u64;
            while !cursor.is_empty() && !new_chain.contains(&cursor) {
                if rollback_count >= MAX_REORG_DEPTH {
                    return Err(NodeError::BlockRejected(format!(
                        "reorg rollback depth {} exceeds MAX_REORG_DEPTH", rollback_count
                    )));
                }
                self.utxo_set.rollback_block_undo(&cursor).map_err(|e| {
                    slog_error!("node", "rollback_failed", block => &cursor, error => &format!("{}", e));
                    NodeError::BlockRejected(format!("rollback failed for {}: {}", cursor, e))
                })?;
                // Contract state rollback + receipt purge.
                self.rollback_contract_block(&cursor);
                rolled_back_old.push(cursor.clone());
                rollback_count += 1;
                // Walk to parent via selected_parent
                cursor = self.block_store.get_block(&cursor)
                    .and_then(|b| b.header.selected_parent.clone())
                    .unwrap_or_default();
            }
            if rollback_count > 0 {
                slog_info!("node", "reorg_rollback_complete", blocks => rollback_count);
            }
        }

        // Apply blocks in GHOSTDAG order (new chain)
        // Track successfully applied blocks so we can rollback on partial failure
        let mut applied_new: Vec<String> = Vec::new();

        for block_hash in &new_chain {
            // Skip if already applied
            if self.utxo_set.get_commitment(block_hash).is_some() {
                continue;
            }

            if let Some(block) = self.block_store.get_block(block_hash) {
                // ── CONTRACT EXECUTION (before UTXO processing) ─────────
                // Uses the persistent contract storage (not temp_dir).
                // State is persisted with undo data after UTXO succeeds.
                let (receipts, receipt_root, state_root, env) =
                    self.execute_contract_transactions(&block, &self.contract_storage);

                // ── UTXO APPLICATION ──────────────────────────────────────
                match self.utxo_set.apply_block_dag_ordered(
                    &block.body.transactions,
                    block.header.height,
                    block_hash,
                ) {
                    Ok((_applied, _skipped, applied_fees)) => {
                        applied_new.push(block_hash.clone());

                        // UTXO succeeded → persist contract state with
                        // undo data in a SINGLE atomic WriteBatch. The
                        // roots are passed in so they land inside the
                        // same batch as the state changes — no second
                        // non-atomic `save_undo(…)` hand-off is
                        // needed.
                        //
                        // On failure the block is already inconsistent
                        // (UTXO committed, contract state did not),
                        // so we MUST roll back every block we've
                        // applied this reorg and surface the error.
                        // Continuing would persist receipts + header
                        // roots for a block whose contract state
                        // never landed, which is worse than any other
                        // failure mode we handle here.
                        if let Err(e) = env.persist_with_undo(
                            &self.contract_storage,
                            block_hash,
                            receipt_root.clone(),
                            state_root.clone(),
                        ) {
                            slog_error!("node", "contract_persist_with_undo_failed",
                                block => block_hash, error => &format!("{}", e));
                            for hash in applied_new.iter().rev() {
                                let _ = self.utxo_set.rollback_block_undo(hash);
                                self.rollback_contract_block(hash);
                            }
                            // Best-effort: re-apply the old chain to restore the
                            // previous consistent state. If this also fails, the
                            // node is in an unrecoverable state and should restart
                            // with full UTXO rebuild.
                            for hash in rolled_back_old.iter().rev() {
                                if let Some(old_block) = self.block_store.get_block(hash) {
                                    let _ = self.utxo_set.apply_block_dag_ordered(
                                        &old_block.body.transactions,
                                        old_block.header.height,
                                        hash,
                                    );
                                }
                            }
                            return Err(NodeError::Consensus(ConsensusError::BlockValidation(
                                format!("contract state persistence failed for block {}: {}",
                                    block_hash, e)
                            )));
                        }

                        // Store receipts in receipt store (in-memory)
                        for r in &receipts {
                            self.receipt_store.track(r.clone());
                        }

                        // Persist receipts to DB
                        use crate::domain::transaction::tx_receipt::persist_receipts_batch;
                        persist_receipts_batch(self.contract_storage.shared_db().as_ref(), &receipts);

                        // Update block header receipt_root and state_root in store.
                        // Uses update_block (not save_block) because the block already
                        // exists — save_block rejects duplicates and would silently fail.
                        if receipt_root.is_some() || state_root.is_some() {
                            if let Some(mut stored_block) = self.block_store.get_block(block_hash) {
                                stored_block.header.receipt_root = receipt_root.clone();
                                stored_block.header.state_root = state_root.clone();
                                if !self.block_store.update_block(&stored_block) {
                                    slog_error!("node", "block_header_update_failed",
                                        block => block_hash,
                                        reason => "update_block returned false — receipt_root/state_root not persisted"
                                    );
                                }
                            }
                        }

                        // ── OBSERVABILITY + INVARIANT CHECK ──────────────────
                        // Record VM metrics for monitoring dashboards and
                        // run a quick invariant check on receipt/state roots.
                        {
                            use crate::runtime::vm::testing::observability::VM_METRICS;
                            use crate::runtime::vm::testing::invariant_checker::InvariantChecker;

                            VM_METRICS.record_block();

                            let has_contract_txs = block.body.transactions.iter()
                                .any(|tx| matches!(tx.tx_type, TxType::ContractCreate | TxType::ContractCall));
                            if has_contract_txs {
                                VM_METRICS.record_call();
                            }

                            // Quick invariant check: verify receipt_root and state_root
                            if let (Some(ref rr), Some(ref sr)) = (&receipt_root, &state_root) {
                                if !InvariantChecker::quick_check(Some(rr), Some(sr), &receipts, &env) {
                                    slog_error!("node", "INVARIANT_VIOLATION",
                                        block => block_hash, height => &block.header.height.to_string());
                                    VM_METRICS.record_violation();
                                }
                            }
                        }

                        // POST-EXECUTION COINBASE VALIDATION
                        //
                        // Coinbase amounts can only be validated AFTER execution
                        // because applied_fees depend on which txs were skipped.
                        // This is the DEFINITIVE coinbase check.
                        use crate::config::consensus::emission_schedule::EmissionSchedule;
                        let expected_reward = EmissionSchedule::block_reward(block.header.height);
                        let expected_total = expected_reward.checked_add(applied_fees)
                    .ok_or_else(|| {
                        // Rollback partially-applied new chain (UTXO + contract)
                        for hash in applied_new.iter().rev() {
                            let _ = self.utxo_set.rollback_block_undo(hash);
                            self.rollback_contract_block(hash);
                        }
                        // Best-effort: re-apply the old chain to restore the
                        // previous consistent state. If this also fails, the
                        // node is in an unrecoverable state and should restart
                        // with full UTXO rebuild.
                        for hash in rolled_back_old.iter().rev() {
                            if let Some(old_block) = self.block_store.get_block(hash) {
                                let _ = self.utxo_set.apply_block_dag_ordered(
                                    &old_block.body.transactions,
                                    old_block.header.height,
                                    hash,
                                );
                            }
                        }
                        NodeError::Consensus(ConsensusError::BlockValidation("reward + fees overflow".into()))
                    })?;

                        if let Some(cb) = block.body.transactions.first() {
                            if cb.is_coinbase() {
                                let actual_total: u64 = match cb.outputs.iter()
                                    .try_fold(0u64, |acc, o| acc.checked_add(o.amount))
                                {
                                    Some(t) => t,
                                    None => {
                                        slog_error!("node", "coinbase_output_overflow", block => block_hash);
                                        // Rollback partially-applied new chain (UTXO + contract)
                                        for hash in applied_new.iter().rev() {
                                            let _ = self.utxo_set.rollback_block_undo(hash);
                                            self.rollback_contract_block(hash);
                                        }
                                        // Best-effort: re-apply the old chain to restore the
                                        // previous consistent state. If this also fails, the
                                        // node is in an unrecoverable state and should restart
                                        // with full UTXO rebuild.
                                        for hash in rolled_back_old.iter().rev() {
                                            if let Some(old_block) = self.block_store.get_block(hash) {
                                                let _ = self.utxo_set.apply_block_dag_ordered(
                                                    &old_block.body.transactions,
                                                    old_block.header.height,
                                                    hash,
                                                );
                                            }
                                        }
                                        return Err(NodeError::BlockRejected(format!(
                                            "coinbase output overflow in {}", block_hash
                                        )));
                                    }
                                };
                                if actual_total != expected_total {
                                    slog_error!("node", "coinbase_mismatch", block => block_hash, actual => &actual_total.to_string(), expected => &expected_total.to_string());
                                    // Rollback partially-applied new chain (UTXO + contract)
                                    for hash in applied_new.iter().rev() {
                                        let _ = self.utxo_set.rollback_block_undo(hash);
                                        self.rollback_contract_block(hash);
                                    }
                                    // Best-effort: re-apply the old chain to restore the
                                    // previous consistent state. If this also fails, the
                                    // node is in an unrecoverable state and should restart
                                    // with full UTXO rebuild.
                                    for hash in rolled_back_old.iter().rev() {
                                        if let Some(old_block) = self.block_store.get_block(hash) {
                                            let _ = self.utxo_set.apply_block_dag_ordered(
                                                &old_block.body.transactions,
                                                old_block.header.height,
                                                hash,
                                            );
                                        }
                                    }
                                    return Err(NodeError::BlockRejected(format!(
                                        "coinbase mismatch in {}: actual={}, expected={}",
                                        block_hash, actual_total, expected_total
                                    )));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // UTXO failed → rollback contract state too
                        slog_error!("node", "utxo_apply_failed",
                            block => block_hash, error => &format!("{}", e));
                        // Rollback partially-applied new chain (UTXO + contract)
                        for hash in applied_new.iter().rev() {
                            let _ = self.utxo_set.rollback_block_undo(hash);
                            self.rollback_contract_block(hash);
                        }
                        // Best-effort: re-apply the old chain to restore the
                        // previous consistent state. If this also fails, the
                        // node is in an unrecoverable state and should restart
                        // with full UTXO rebuild.
                        for hash in rolled_back_old.iter().rev() {
                            if let Some(old_block) = self.block_store.get_block(hash) {
                                let _ = self.utxo_set.apply_block_dag_ordered(
                                    &old_block.body.transactions,
                                    old_block.header.height,
                                    hash,
                                );
                            }
                        }
                        return Err(NodeError::BlockRejected(format!(
                            "apply_block_dag_ordered failed for {}: {}", block_hash, e
                        )));
                    }
                }
            } else {
                // Missing block in store — rollback partially-applied new chain (UTXO + contract)
                for hash in applied_new.iter().rev() {
                    let _ = self.utxo_set.rollback_block_undo(hash);
                    self.rollback_contract_block(hash);
                }
                // Best-effort: re-apply the old chain to restore the
                // previous consistent state. If this also fails, the
                // node is in an unrecoverable state and should restart
                // with full UTXO rebuild.
                for hash in rolled_back_old.iter().rev() {
                    if let Some(old_block) = self.block_store.get_block(hash) {
                        let _ = self.utxo_set.apply_block_dag_ordered(
                            &old_block.body.transactions,
                            old_block.header.height,
                            hash,
                        );
                    }
                }
                return Err(NodeError::BlockRejected(format!(
                    "block {} missing from store during virtual chain apply", block_hash
                )));
            }
        }

        // Update best hash
        if !self.block_store.update_best_hash(&best_tip) {
            // Rollback everything we just applied — the tip cannot be
            // authoritative without a persisted best_hash pointer.
            for hash in applied_new.iter().rev() {
                let _ = self.utxo_set.rollback_block_undo(hash);
                self.rollback_contract_block(hash);
            }
            // Best-effort: re-apply the old chain to restore the
            // previous consistent state. If this also fails, the
            // node is in an unrecoverable state and should restart
            // with full UTXO rebuild.
            for hash in rolled_back_old.iter().rev() {
                if let Some(old_block) = self.block_store.get_block(hash) {
                    let _ = self.utxo_set.apply_block_dag_ordered(
                        &old_block.body.transactions,
                        old_block.header.height,
                        hash,
                    );
                }
            }
            return Err(NodeError::Consensus(ConsensusError::BlockValidation(
                format!("failed to persist best_hash for tip {}", best_tip)
            )));
        }

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
                    blue_score:      best_block.header.blue_score,
                });
                // Publish for RPC getblocktemplate — write to both
                // the per-instance cell (the canonical reader for
                // RPC handlers that hold an `Arc<MiningTemplateState>`
                // via `RpcState`) and the process-default cell
                // (retained so the legacy free-function readers
                // still observe the current value).
                self.mining_state.set_next_difficulty(next_diff);
                set_next_difficulty(next_diff);
            }
        }

        // Update DAG tips for getblocktemplate — miners need current tips as parents
        let tips = self.dag_manager.get_tips();
        if !tips.is_empty() {
            self.mining_state.set_dag_tips(tips.clone());
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
                    // that still have undo data (UTXO or contract — batch prune them)
                    let mut to_prune: Vec<String> = Vec::new();
                    // Walk the canonical chain below the tip to find
                    // ALL blocks with undo data at or below finality
                    // height — not just the new_chain segment, which
                    // in the common (non-reorg) case is a single
                    // block and would never reach old-enough heights.
                    {
                        let mut cursor = best_tip.clone();
                        let mut walk_limit = 0u64;
                        while !cursor.is_empty() && walk_limit < FINALITY_DEPTH * 2 {
                            walk_limit += 1;
                            if let Some(b) = self.block_store.get_block(&cursor) {
                                if b.header.height <= finality_height {
                                    if self.utxo_set.has_undo_data(&cursor)
                                        || self.contract_storage.has_undo_data(&cursor)
                                    {
                                        to_prune.push(cursor.clone());
                                    }
                                    // Stop once we've walked past the
                                    // finality boundary by a margin —
                                    // anything deeper was already pruned.
                                    if b.header.height + 10 < finality_height {
                                        break;
                                    }
                                }
                                cursor = b.header.selected_parent
                                    .clone()
                                    .unwrap_or_default();
                            } else {
                                break;
                            }
                        }
                    }
                    if !to_prune.is_empty() {
                        let pruned = self.utxo_set.prune_finalized_undo_data(&to_prune);
                        let contract_pruned = self.contract_storage.prune_finalized_undo_data(&to_prune);
                        if pruned > 0 || contract_pruned > 0 {
                            slog_info!("node", "pruned_undo_entries",
                                utxo_count => &pruned.to_string(),
                                contract_count => &contract_pruned.to_string(),
                                finality_height => &finality_height.to_string());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════
    // CONTRACT EXECUTION
    // ═══════════════════════════════════════════════════════════════════

    /// Roll back a block's contract execution footprint in a single
    /// consistent step:
    ///
    ///   1. Replay the block's contract undo record so the on-disk
    ///      contract state matches the pre-block view.
    ///   2. Delete every persisted receipt for the block's TX set
    ///      (both from the RocksDB `receipt:*` prefix and from the
    ///      in-memory `ReceiptStore`), so RPC clients stop seeing
    ///      receipts that correspond to an orphaned block.
    ///
    /// Previously, rollback paths only called
    /// `ContractStorage::rollback_block` and left the receipts in
    /// place. RPC clients could then `eth_getTransactionReceipt` a
    /// TX from the orphaned block and get back a receipt marked as
    /// "included in block X" where block X is no longer part of the
    /// canonical chain — a stale read that confuses every indexer.
    fn rollback_contract_block(&self, block_hash: &str) {
        // Contract state rollback — best-effort, a missing undo is
        // non-fatal because some blocks may not have had any
        // contract TXs and therefore carry no undo record.
        if let Err(e) = self.contract_storage.rollback_block(block_hash) {
            crate::slog_warn!("node", "contract_rollback_skipped",
                block => block_hash, error => &format!("{}", e));
        }

        // Remove receipts for every TX in the block.
        if let Some(block) = self.block_store.get_block(block_hash) {
            let tx_hashes: Vec<String> = block
                .body
                .transactions
                .iter()
                .map(|tx| tx.hash.clone())
                .collect();
            if !tx_hashes.is_empty() {
                use crate::domain::transaction::tx_receipt::delete_receipts_for_block;
                delete_receipts_for_block(
                    self.contract_storage.shared_db().as_ref(),
                    &tx_hashes,
                );
                self.receipt_store.remove_tx_hashes(&tx_hashes);
            }
        }
    }

    /// Execute contract transactions (ContractCreate, ContractCall) within a block.
    ///
    /// Uses a SINGLE shared ExecutionEnvironment across all TXs in the block
    /// so contract state is visible between TXs. Does NOT persist state
    /// internally — the caller must persist via env.persist_with_undo()
    /// only after UTXO application succeeds (atomic pipeline).
    ///
    /// Returns (receipts, receipt_root, state_root, env):
    ///   - receipts: TxReceipt for each TX in the block
    ///   - receipt_root: SHA-256 of sorted receipt data (None if no contract TXs)
    ///   - state_root: StateManager root hash (None if no contract TXs)
    ///   - env: the ExecutionEnvironment (caller persists with undo on UTXO success)
    ///
    /// Takes `&self` so the VM's block context inherits the node's real
    /// `NetworkMode` (the previous free-function form unconditionally
    /// labelled the environment as "mainnet", so a testnet/regtest
    /// deploy synthesized mainnet-style fallback addresses whenever the
    /// address registry missed).
    fn execute_contract_transactions(
        &self,
        block: &Block,
        contract_storage: &ContractStorage,
    ) -> (Vec<TxReceipt>, Option<String>, Option<String>, ExecutionEnvironment) {
        // Thread the node's actual network through to the VM so
        // `resolve_address` fallbacks use the right prefix.
        let network_short = self.network.short_name().to_string();

        // Wire up lazy contract loading so nested CALLs into
        // addresses that weren't explicitly preloaded (because
        // they weren't direct TX targets in this block) can
        // load their code from disk on first touch.
        let mut env = ExecutionEnvironment::new(BlockContext {
            timestamp: block.header.timestamp,
            block_hash: block.header.hash.clone(),
            network: network_short,
        })
        .with_lazy_load_storage(Arc::clone(&self.contract_storage));

        let mut receipts = Vec::with_capacity(block.body.transactions.len());
        let mut has_contract_txs = false;

        // Pre-load referenced contracts from storage. `load_contract_from_storage`
        // returns `Err` only when the on-disk state exists but is corrupt
        // (distinct from "genuinely absent"). A corrupt record is a
        // consensus-visible data-integrity problem that the block executor
        // must NOT paper over by silently continuing — doing so would
        // execute later TXs against a stale/zeroed contract and diverge
        // from the rest of the network. We emit an `Error` receipt for
        // every contract TX in the block so the block commits cleanly
        // (receipts + state remain consistent) but no contract code is
        // actually executed against a corrupt substrate.
        let mut preload_error: Option<String> = None;
        for tx in &block.body.transactions {
            match tx.tx_type {
                TxType::ContractCreate => {
                    let deployer = tx.inputs.first()
                        .map(|i| i.owner.clone())
                        .unwrap_or_default();
                    if let Err(e) = env.load_contract_from_storage(contract_storage, &deployer) {
                        crate::slog_error!("vm", "preload_deployer_corrupt_surfacing_as_error",
                            deployer => &deployer, error => &format!("{}", e));
                        preload_error = Some(format!(
                            "corrupt contract state for deployer '{}': {}",
                            deployer, e
                        ));
                        break;
                    }
                }
                TxType::ContractCall => {
                    // Reject a ContractCall that doesn't set `contract_address`
                    // explicitly. The previous fallback to `outputs[0].address`
                    // meant a malformed tx could silently execute against the
                    // recipient of the value transfer, which is a completely
                    // different contract.
                    let target = match tx.contract_address.as_ref() {
                        Some(a) if !a.is_empty() => a.clone(),
                        _ => {
                            crate::slog_error!("vm", "contract_call_missing_contract_address",
                                tx => &tx.hash);
                            preload_error = Some(format!(
                                "ContractCall tx '{}' has no contract_address", tx.hash
                            ));
                            break;
                        }
                    };
                    if let Err(e) = env.load_contract_from_storage(contract_storage, &target) {
                        crate::slog_error!("vm", "preload_target_corrupt_surfacing_as_error",
                            target => &target, error => &format!("{}", e));
                        preload_error = Some(format!(
                            "corrupt contract state for target '{}': {}",
                            target, e
                        ));
                        break;
                    }
                    let caller = tx.inputs.first()
                        .map(|i| i.owner.clone())
                        .unwrap_or_default();
                    if let Err(e) = env.load_contract_from_storage(contract_storage, &caller) {
                        crate::slog_error!("vm", "preload_caller_corrupt_surfacing_as_error",
                            caller => &caller, error => &format!("{}", e));
                        preload_error = Some(format!(
                            "corrupt contract state for caller '{}': {}",
                            caller, e
                        ));
                        break;
                    }
                }
                _ => {}
            }
        }

        // If pre-load surfaced corruption, degrade the whole block's
        // contract TXs to Error receipts and skip execution. The block
        // still commits (UTXO + receipts remain consistent) but no
        // contract code runs against corrupt state.
        if let Some(msg) = preload_error {
            for (tx_index, tx) in block.body.transactions.iter().enumerate() {
                let is_contract_tx = matches!(
                    tx.tx_type,
                    TxType::ContractCreate | TxType::ContractCall
                );
                if is_contract_tx {
                    has_contract_txs = true;
                    receipts.push(TxReceipt::from_execution(
                        &tx.hash,
                        &ExecutionResult::Error { gas_used: 0, message: msg.clone() },
                        &block.header.hash, block.header.height, tx_index as u32,
                    ));
                } else {
                    receipts.push(TxReceipt::from_execution(
                        &tx.hash,
                        &ExecutionResult::Success { gas_used: 0, return_data: vec![], logs: vec![] },
                        &block.header.hash, block.header.height, tx_index as u32,
                    ));
                }
            }
            let (receipt_root, state_root) = if has_contract_txs {
                (Some(compute_receipt_root(&receipts)), Some(env.state.state_root()))
            } else {
                (None, None)
            };
            return (receipts, receipt_root, state_root, env);
        }

        // Execute each TX in block order through the shared environment
        for (tx_index, tx) in block.body.transactions.iter().enumerate() {
            // Reset per-TRANSACTION VM state so EIP-6780's
            // `created_in_tx` and EIP-211's `last_return_data`
            // don't leak between sibling TXs inside the same block.
            // The previous implementation only created one env per
            // block and never reset these fields between TXs, so a
            // SELFDESTRUCT in TX N+1 could observe a contract as
            // "created in the same tx" because TX N had created it,
            // and a RETURNDATASIZE in TX N+1 could read the trailing
            // bytes TX N's last CALL left behind.
            env.begin_tx();

            match tx.tx_type {
                TxType::ContractCreate => {
                    has_contract_txs = true;

                    // Read bytecode from tx.deploy_code (canonical), fall back to payload_hash (legacy)
                    let payload = if let Some(ref code) = tx.deploy_code {
                        code.clone()
                    } else {
                        match &tx.payload_hash {
                            Some(ph) => match hex::decode(ph) {
                                Ok(bytes) => bytes,
                                Err(_) => {
                                    receipts.push(TxReceipt::from_execution(
                                        &tx.hash,
                                        &ExecutionResult::Error { gas_used: 0, message: "invalid deploy payload".into() },
                                        &block.header.hash, block.header.height, tx_index as u32,
                                    ));
                                    continue;
                                },
                            },
                            None => {
                                receipts.push(TxReceipt::from_execution(
                                    &tx.hash,
                                    &ExecutionResult::Error { gas_used: 0, message: "missing deploy payload".into() },
                                    &block.header.hash, block.header.height, tx_index as u32,
                                ));
                                continue;
                            },
                        }
                    };

                    let deployer = tx.inputs.first()
                        .map(|i| i.owner.clone())
                        .unwrap_or_default();
                    if deployer.is_empty() {
                        receipts.push(TxReceipt::from_execution(
                            &tx.hash,
                            &ExecutionResult::Error { gas_used: 0, message: "ContractCreate missing deployer (no inputs)".into() },
                            &block.header.hash, block.header.height, tx_index as u32,
                        ));
                        continue;
                    }
                    let value = tx.outputs.first()
                        .map(|o| o.amount)
                        .unwrap_or(0);
                    let gas_limit = tx.gas_limit.unwrap_or(10_000_000u64);

                    // Compute the contract address via the canonical
                    // `ContractDeployer::compute_create_address`
                    // helper so the block-apply path produces the
                    // SAME address the inline CREATE opcode and the
                    // executor deploy path produce for the same
                    // inputs. The previous ad-hoc
                    // `sha256(deployer || payload || 0)` disagreed
                    // on every axis:
                    //
                    //   - no network prefix → no `SD1c…` /
                    //     `ST1c…` form, so the stored address
                    //     couldn't round-trip through the address
                    //     registry,
                    //   - no domain separator → hash collided with
                    //     any other (deployer, payload) pair that
                    //     any other code happened to hash,
                    //   - fixed `nonce = 0` → re-deploying the same
                    //     code from the same deployer always
                    //     landed at the same address (guaranteed
                    //     EIP-684 collision after the first deploy).
                    //
                    // We read the deployer's current nonce from
                    // state and increment it after a successful
                    // deploy, matching Ethereum's CREATE semantics.
                    let deployer_nonce = env.state.get_nonce(&deployer);
                    let contract_addr = match crate::runtime::vm::contracts::contract_deployer::ContractDeployer::compute_create_address(&deployer, deployer_nonce) {
                        Ok(addr) => addr,
                        Err(e) => {
                            slog_error!("node", "contract_deploy_address_derivation_failed",
                                tx => &tx.hash, deployer => &deployer, error => &format!("{}", e));
                            receipts.push(TxReceipt::from_execution(
                                &tx.hash,
                                &ExecutionResult::Error {
                                    gas_used: 0,
                                    message: format!("contract address derivation failed: {}", e),
                                },
                                &block.header.hash, block.header.height, tx_index as u32,
                            ));
                            continue;
                        }
                    };

                    // Take a snapshot BEFORE installing the init code
                    // so a failing constructor / rejected runtime
                    // code can roll back every side effect —
                    // including the temporary `set_code(init)` and
                    // any storage mutations the constructor made.
                    // The previous code installed the init code
                    // outside any snapshot, so a failing
                    // constructor left the init code sitting in
                    // state: a subsequent call to that address
                    // would run the init code as runtime code, which
                    // is a completely different EVM program.
                    let deploy_snapshot = env.state.snapshot();

                    // Phase 1: Install the INIT code as the new contract's
                    // temporary code so execute_frame has something to run.
                    if let Err(e) = env.state.set_code(&contract_addr, payload.to_vec()) {
                        env.state.rollback(deploy_snapshot).ok();
                        slog_error!("node", "contract_deploy_init_set_code_failed",
                            tx => &tx.hash, address => &contract_addr, error => &format!("{}", e));
                        receipts.push(TxReceipt::from_execution(
                            &tx.hash,
                            &ExecutionResult::Error {
                                gas_used: 0,
                                message: format!("init code set failed: {}", e),
                            },
                            &block.header.hash, block.header.height, tx_index as u32,
                        ));
                        continue;
                    }

                    let call_ctx = CallContext {
                        address: contract_addr.clone(),
                        code_address: contract_addr.clone(),
                        caller: deployer.clone(),
                        value,
                        gas_limit,
                        calldata: vec![],
                        is_static: false,
                        depth: 0,
                        is_delegate: false,
                    };

                    // Phase 2: Run the constructor.
                    let outcome = env.execute_frame(&call_ctx);
                    let exec_result = match outcome {
                        CallOutcome::Success { gas_used, return_data, logs } => {
                            // Phase 3: If the constructor RETURNed a non-empty
                            // payload, that's the RUNTIME code — replace the
                            // init code with it and validate (EIP-3541, size).
                            // If RETURN was empty, keep the init code as the
                            // runtime code — the simple "raw runtime" pattern.
                            if !return_data.is_empty() {
                                match crate::runtime::vm::contracts::contract_deployer::ContractDeployer::validate_runtime_code(&return_data) {
                                    Ok(()) => {
                                        if let Err(e) = env.state.set_code(&contract_addr, return_data.clone()) {
                                            // set_code of runtime code
                                            // failed — roll the entire
                                            // deployment back so neither
                                            // the init code NOR the
                                            // constructor's storage
                                            // mutations linger.
                                            env.state.rollback(deploy_snapshot).ok();
                                            slog_error!("node", "contract_deploy_runtime_set_code_failed",
                                                tx => &tx.hash, address => &contract_addr, error => &format!("{}", e));
                                            receipts.push(TxReceipt::from_execution(
                                                &tx.hash,
                                                &ExecutionResult::Error {
                                                    gas_used,
                                                    message: format!("runtime code set failed: {}", e),
                                                },
                                                &block.header.hash, block.header.height, tx_index as u32,
                                            ));
                                            continue;
                                        }
                                    }
                                    Err(e) => {
                                        // Invalid runtime code (e.g. 0xEF
                                        // prefix per EIP-3541). Roll back
                                        // EVERY constructor side effect —
                                        // including init code, storage
                                        // writes, transferred value —
                                        // so the failed deploy is
                                        // indistinguishable from "never
                                        // happened". The previous code
                                        // left the init code + storage
                                        // committed and only emitted an
                                        // Error receipt.
                                        env.state.rollback(deploy_snapshot).ok();
                                        slog_error!("node", "contract_deploy_runtime_code_rejected",
                                            tx => &tx.hash,
                                            address => &contract_addr,
                                            error => &format!("{}", e));
                                        receipts.push(TxReceipt::from_execution(
                                            &tx.hash,
                                            &ExecutionResult::Error {
                                                gas_used,
                                                message: format!("invalid runtime code returned from constructor: {}", e),
                                            },
                                            &block.header.hash,
                                            block.header.height,
                                            tx_index as u32,
                                        ));
                                        continue;
                                    }
                                }
                            }
                            // Success path: commit the snapshot and
                            // bump the deployer's nonce. The nonce
                            // bump is what guarantees that the next
                            // deploy from the same deployer lands at
                            // a distinct contract address — failing
                            // to increment it would let every
                            // subsequent ContractCreate collide.
                            env.state.commit(deploy_snapshot).ok();
                            let _ = env.state.increment_nonce(&deployer);
                            ExecutionResult::Success { gas_used, return_data, logs }
                        }
                        CallOutcome::Revert { gas_used, return_data } => {
                            // Revert path: roll back the init
                            // code + constructor effects, not just
                            // the call's own snapshot. The
                            // inner `execute_frame` already rolled
                            // back its own nested snapshot, but the
                            // `set_code(init)` we did above was
                            // OUTSIDE that nested snapshot, so we
                            // still need to rewind our own one.
                            env.state.rollback(deploy_snapshot).ok();
                            ExecutionResult::Revert { gas_used, reason: String::from_utf8_lossy(&return_data).to_string() }
                        }
                        CallOutcome::Failure { gas_used } => {
                            // Same rollback reasoning as Revert.
                            env.state.rollback(deploy_snapshot).ok();
                            // Map to `Error` instead of `OutOfGas`:
                            // `CallOutcome::Failure` covers stack
                            // underflow, static violations, value
                            // transfer rejection, invalid opcode,
                            // and depth limit in addition to true
                            // out-of-gas. Labelling every one of
                            // those as `OutOfGas` in the receipt
                            // misleads RPC clients that rely on the
                            // variant tag to decide whether to
                            // retry with more gas.
                            ExecutionResult::Error {
                                gas_used,
                                message: "constructor execution failed".into(),
                            }
                        }
                    };

                    let mut receipt = TxReceipt::from_execution(
                        &tx.hash, &exec_result, &block.header.hash,
                        block.header.height, tx_index as u32,
                    );
                    receipt.contract_addr = Some(contract_addr.clone());

                    match &exec_result {
                        ExecutionResult::Success { gas_used, .. } => {
                            slog_info!("node", "contract_deployed",
                                address => &contract_addr,
                                gas_used => &gas_used.to_string(),
                                receipt_success => "true");
                        }
                        _ => {
                            slog_warn!("node", "contract_deploy_execution_failed",
                                tx => &tx.hash, address => &contract_addr,
                                receipt_success => "false");
                        }
                    }
                    receipts.push(receipt);
                }
                TxType::ContractCall => {
                    has_contract_txs = true;

                    // `contract_address` is REQUIRED. The fallback
                    // to `outputs[0].address` silently rerouted
                    // calls to whatever address happened to be the
                    // recipient of the value transfer — a completely
                    // different contract.
                    let target = match tx.contract_address.as_ref() {
                        Some(a) if !a.is_empty() => a.clone(),
                        _ => {
                            receipts.push(TxReceipt::from_execution(
                                &tx.hash,
                                &ExecutionResult::Error {
                                    gas_used: 0,
                                    message: "ContractCall missing contract_address".into(),
                                },
                                &block.header.hash, block.header.height, tx_index as u32,
                            ));
                            continue;
                        }
                    };
                    let calldata = if let Some(ref cd) = tx.calldata {
                        cd.clone()
                    } else {
                        match &tx.payload_hash {
                            Some(ph) => match hex::decode(ph) {
                                Ok(bytes) => bytes,
                                Err(_) => {
                                    receipts.push(TxReceipt::from_execution(
                                        &tx.hash,
                                        &ExecutionResult::Error { gas_used: 0, message: "invalid calldata".into() },
                                        &block.header.hash, block.header.height, tx_index as u32,
                                    ));
                                    continue;
                                },
                            },
                            None => {
                                receipts.push(TxReceipt::from_execution(
                                    &tx.hash,
                                    &ExecutionResult::Error { gas_used: 0, message: "missing calldata".into() },
                                    &block.header.hash, block.header.height, tx_index as u32,
                                ));
                                continue;
                            },
                        }
                    };
                    let caller = tx.inputs.first()
                        .map(|i| i.owner.clone())
                        .unwrap_or_default();
                    if caller.is_empty() {
                        receipts.push(TxReceipt::from_execution(
                            &tx.hash,
                            &ExecutionResult::Error { gas_used: 0, message: "ContractCall missing caller (no inputs)".into() },
                            &block.header.hash, block.header.height, tx_index as u32,
                        ));
                        continue;
                    }
                    let value = tx.outputs.first()
                        .map(|o| o.amount)
                        .unwrap_or(0);
                    let gas_limit = tx.gas_limit.unwrap_or(10_000_000u64);

                    // Lazy-load the target's code from disk on
                    // first touch. `load_contract_from_storage`
                    // only populates the account row; the code
                    // blob lives under `code:{addr}` and is read
                    // here. Previously this was a no-error `.ok()`
                    // — so a set_code failure (disk full,
                    // permissions, corruption) silently dropped
                    // the contract's runtime code and the CALL
                    // executed as if it were an empty address.
                    if let Some(code_hex) = contract_storage.get_state(&format!("code:{}", target)) {
                        match hex::decode(&code_hex) {
                            Ok(code) => {
                                if env.state.get_code(&target).is_empty() {
                                    if let Err(e) = env.state.set_code(&target, code) {
                                        slog_error!("node", "contract_call_code_load_set_code_failed",
                                            target => &target, error => &format!("{}", e));
                                        receipts.push(TxReceipt::from_execution(
                                            &tx.hash,
                                            &ExecutionResult::Error {
                                                gas_used: 0,
                                                message: format!("load contract code: {}", e),
                                            },
                                            &block.header.hash, block.header.height, tx_index as u32,
                                        ));
                                        continue;
                                    }
                                }
                            }
                            Err(e) => {
                                slog_error!("node", "contract_call_code_hex_corrupt",
                                    target => &target, error => &format!("{}", e));
                                receipts.push(TxReceipt::from_execution(
                                    &tx.hash,
                                    &ExecutionResult::Error {
                                        gas_used: 0,
                                        message: format!("contract code is not valid hex: {}", e),
                                    },
                                    &block.header.hash, block.header.height, tx_index as u32,
                                ));
                                continue;
                            }
                        }
                    }

                    let call_ctx = CallContext {
                        address: target.clone(),
                        code_address: target.clone(),
                        caller: caller.clone(),
                        value,
                        gas_limit,
                        calldata,
                        is_static: false,
                        depth: 0,
                        is_delegate: false,
                    };

                    let outcome = env.execute_frame(&call_ctx);
                    let exec_result = match outcome {
                        CallOutcome::Success { gas_used, return_data, logs } => {
                            ExecutionResult::Success { gas_used, return_data, logs }
                        }
                        CallOutcome::Revert { gas_used, return_data } => {
                            ExecutionResult::Revert { gas_used, reason: String::from_utf8_lossy(&return_data).to_string() }
                        }
                        CallOutcome::Failure { gas_used } => {
                            // See the ContractCreate branch above
                            // for why Failure → Error, not OutOfGas.
                            ExecutionResult::Error {
                                gas_used,
                                message: "contract call failed".into(),
                            }
                        }
                    };

                    let receipt = TxReceipt::from_execution(
                        &tx.hash, &exec_result, &block.header.hash,
                        block.header.height, tx_index as u32,
                    );

                    match &exec_result {
                        ExecutionResult::Success { gas_used, .. } => {
                            slog_info!("node", "contract_called",
                                target => &target,
                                gas_used => &gas_used.to_string(),
                                receipt_success => &receipt.execution_success.to_string());
                        }
                        _ => {
                            slog_warn!("node", "contract_call_failed",
                                tx => &tx.hash,
                                receipt_success => &receipt.execution_success.to_string());
                        }
                    }
                    receipts.push(receipt);
                }
                _ => {
                    // Non-contract TXs get empty receipts for receipt root computation
                    receipts.push(TxReceipt::from_execution(
                        &tx.hash,
                        &ExecutionResult::Success { gas_used: 0, return_data: vec![], logs: vec![] },
                        &block.header.hash, block.header.height, tx_index as u32,
                    ));
                }
            }
        }

        // Compute receipt_root and state_root only if there were contract TXs
        let (receipt_root, state_root) = if has_contract_txs {
            let rr = compute_receipt_root(&receipts);
            let sr = env.state.state_root();
            (Some(rr), Some(sr))
        } else {
            (None, None)
        };

        (receipts, receipt_root, state_root, env)
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

        let mut queue: Vec<(String, usize)> = vec![(parent_hash.to_string(), 0)];
        let mut total_processed = 0usize;
        const MAX_TOTAL_ORPHANS: usize = 256; // prevent runaway processing

        while let Some((current_parent, chain_depth)) = queue.pop() {
            total_processed += 1;
            if chain_depth > MAX_ORPHAN_DEPTH || total_processed > MAX_TOTAL_ORPHANS {
                slog_warn!("node", "orphan_chain_limit_exceeded",
                    depth => &chain_depth.to_string(),
                    total => &total_processed.to_string());
                break;
            }

            let waiting: Vec<String> = match self.orphan_by_parent.lock() {
                Ok(mut by_parent) => {
                    by_parent.remove(&current_parent).unwrap_or_default()
                }
                Err(_) => continue,
            };

            // Remove from pool, preserving (block, timestamp, peer_id) for re-insertion on failure
            let mut entries_to_process: Vec<(Block, u64, String)> = Vec::new();
            if let Ok(mut pool) = self.orphan_pool.lock() {
                for hash in &waiting {
                    if let Some(entry) = pool.remove(hash) {
                        entries_to_process.push(entry);
                    }
                }
            }

            for (block, timestamp, peer_id) in entries_to_process {
                let hash = block.header.hash.clone();
                match self.process_block_without_orphans(&block) {
                    Ok(()) => {
                        // Success — decrement peer count and queue children
                        if let Ok(mut counts) = self.orphan_count_by_peer.lock() {
                            if let Some(c) = counts.get_mut(&peer_id) {
                                *c = c.saturating_sub(1);
                                if *c == 0 { counts.remove(&peer_id); }
                            }
                        }
                        queue.push((hash, chain_depth + 1));
                    }
                    Err(ref e) if e.to_string().contains("not found") => {
                        // Still orphan — re-insert into pool and parent index
                        if let Ok(mut pool) = self.orphan_pool.lock() {
                            pool.insert(hash.clone(), (block.clone(), timestamp, peer_id));
                        }
                        if let Ok(mut by_parent) = self.orphan_by_parent.lock() {
                            for p in &block.header.parents {
                                by_parent.entry(p.clone())
                                    .or_insert_with(Vec::new)
                                    .push(hash.clone());
                            }
                        }
                    }
                    Err(e) => {
                        // Permanent failure — decrement peer count, log warning
                        if let Ok(mut counts) = self.orphan_count_by_peer.lock() {
                            if let Some(c) = counts.get_mut(&peer_id) {
                                *c = c.saturating_sub(1);
                                if *c == 0 { counts.remove(&peer_id); }
                            }
                        }
                        slog_warn!("node", "orphan_processing_failed",
                            hash => &hash, error => &format!("{}", e));
                    }
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
        if let Err(e) = self.ghostdag.add_block(dag_block) {
            // Cleanup: remove from BlockStore since GHOSTDAG rejected
            let _ = self.block_store.delete_block(&block.header.hash);
            slog_error!("node", "ghostdag_add_failed_cleanup",
                hash => &block.header.hash, error => &e.to_string(),
                note => "block removed from BlockStore; DAG entry may be stale until reindex");
            return Err(NodeError::BlockRejected(format!("GHOSTDAG: {}", e)));
        }

        // UTXO write + commitment ATOMICALLY (validation already passed in Phase 1)
        let _commitment = self.utxo_set.apply_block_write_with_commitment(
            &block.body.transactions, 0, &block.header.hash
        ).map_err(|e| NodeError::BlockRejected(format!("Genesis UTXO write failed: {}", e)))?;

        // Genesis is always best
        if !self.block_store.update_best_hash(&block.header.hash) {
            return Err(NodeError::BlockRejected(
                "Failed to persist best_hash for genesis block".to_string()
            ));
        }

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
