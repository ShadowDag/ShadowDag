// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;

use crate::domain::block::block::Block;
use crate::domain::utxo::utxo_set::UtxoSet;

use crate::config::node::node_config::NetworkMode;
use crate::engine::consensus::validation::block_validator::BlockValidator;

use crate::engine::consensus::difficulty::retarget::{
    BlockTimeRecord, RetargetEngine, SHORT_WINDOW,
};
use crate::engine::dag::core::dag_manager::DagManager;
use crate::engine::dag::ghostdag::ghostdag::{DagBlock, GhostDag};

use crate::domain::transaction::transaction::TxType;
use crate::domain::transaction::tx_receipt::{compute_receipt_root, ReceiptStore, TxReceipt};
use crate::errors::{ConsensusError, NodeError};
use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;
use crate::runtime::vm::contracts::contract_storage::ContractStorage;
use crate::runtime::vm::core::execution_env::{
    BlockContext, CallContext, CallOutcome, ExecutionEnvironment,
};
use crate::runtime::vm::core::vm::ExecutionResult;
use crate::service::network::dos_guard::{DosGuard, DosVerdict, MsgType};
use crate::{slog_error, slog_info, slog_warn};

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
    dag_tips: Mutex<Vec<String>>,
    /// M5: the deferred state commitment for the NEXT block, published by the
    /// node (which has ghostdag + block_store) alongside `next_difficulty` and
    /// anchored on the SAME `select_parent(canonical tips)` — so getblocktemplate
    /// hands the miner exactly the value the validator will recompute from the
    /// block's parents (miner<->verifier parity, mirroring the C4 difficulty path).
    prev_state_commitment: Mutex<Option<String>>,
}

impl MiningTemplateState {
    pub fn new() -> Self {
        Self {
            next_difficulty: AtomicU64::new(1),
            dag_tips: Mutex::new(Vec::new()),
            prev_state_commitment: Mutex::new(None),
        }
    }

    pub fn next_difficulty(&self) -> u64 {
        self.next_difficulty.load(Ordering::Relaxed)
    }

    pub fn set_next_difficulty(&self, diff: u64) {
        self.next_difficulty.store(diff, Ordering::Relaxed);
    }

    pub fn dag_tips(&self) -> Vec<String> {
        self.dag_tips.lock().map(|t| t.clone()).unwrap_or_default()
    }

    pub fn set_dag_tips(&self, tips: Vec<String>) {
        if let Ok(mut t) = self.dag_tips.lock() {
            *t = tips;
        }
    }

    pub fn prev_state_commitment(&self) -> Option<String> {
        self.prev_state_commitment.lock().ok().and_then(|c| c.clone())
    }

    pub fn set_prev_state_commitment(&self, commitment: Option<String>) {
        if let Ok(mut c) = self.prev_state_commitment.lock() {
            *c = commitment;
        }
    }
}

/// M5 SHARED PARITY FUNCTION — the ONE derivation of a block's deferred state
/// commitment, called identically by the template publisher (miner side) and the
/// validator. Anchors on `ghostdag.select_parent(parents)` (the SAME rule the
/// difficulty path uses) and binds that selected parent's IDENTITY ONLY.
/// Genesis / no-parent selection -> `genesis_prev_state_commitment()`.
///
/// SCOPE — read this before citing M5 as a state commitment: the parent's
/// `utxo_commitment` / `state_root` / `receipt_root` are NOT bound. They are
/// passed as canonical `None` (reserved format slots) for the reason spelled out
/// at the call below, so this does NOT yet make the parent's post-execution state
/// a consensus commitment. `state_root` / `receipt_root` are still written into
/// the stored block AFTER execution, outside the PoW hash. Binding them for real
/// is future work and needs deterministic, pre-mine-populated roots.
///
/// A block with these `parents` MUST carry exactly this value in
/// `header.prev_state_commitment`; the validator rejects any mismatch and PoW
/// covers it (it is in the preimage). Because both sides run this function over
/// the same `select_parent(parents)`, they agree.
pub fn expected_prev_state_commitment(
    parents: &[String],
    ghostdag: &GhostDag,
    block_store: &BlockStore,
) -> String {
    use crate::engine::mining::algorithms::shadowhash::{
        compute_prev_state_commitment, genesis_prev_state_commitment,
    };
    let sp = ghostdag.select_parent(parents);
    if sp.is_empty() {
        return genesis_prev_state_commitment();
    }
    // M5 (path B): bind ONLY the deterministic selected-parent identity. The
    // parent's `state_root` / `receipt_root` are DEFERRED, path-dependent EVM
    // roots — populated post-execution and only for executed contract blocks —
    // and `header.utxo_commitment` is not yet deterministically populated.
    // Binding any of them here would let the commitment DIVERGE across nodes and
    // forks (a consensus split): this derivation runs before the parent's roots
    // are recomputed, so a side node may read different values than the miner.
    // The commitment FORMAT keeps the (currently-None) root slots reserved, so a
    // future deterministic-roots upgrade needs no domain-tag change. `block_store`
    // is retained for that upgrade (it will re-read the parent's committed roots).
    let _ = block_store;
    compute_prev_state_commitment(&sp, None, None, None)
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

/// Get the NEXT block's M5 deferred state commitment from the process-default
/// cell. The daemon builds its RPC template with `RpcState::mining_state = None`,
/// so `getblocktemplate` MUST read this fallback (exactly like `get_next_difficulty`
/// / `get_dag_tips`). Without it the template would emit `prev_state_commitment =
/// null`, the miner would stamp `None`, and the M5 verify would reject every
/// height>0 block — a silent chain halt. The FullNode publishes into this cell on
/// startup and after every accepted block, alongside difficulty and tips.
pub fn get_prev_state_commitment() -> Option<String> {
    PROCESS_DEFAULT_MINING_STATE.prev_state_commitment()
}

fn set_prev_state_commitment(commitment: Option<String>) {
    PROCESS_DEFAULT_MINING_STATE.set_prev_state_commitment(commitment)
}

/// Reset the process-default mining template cell. Test-only.
#[cfg(test)]
pub fn reset_mining_globals() {
    PROCESS_DEFAULT_MINING_STATE.set_next_difficulty(0);
    PROCESS_DEFAULT_MINING_STATE.set_dag_tips(Vec::new());
    PROCESS_DEFAULT_MINING_STATE.set_prev_state_commitment(None);
}

/// Maximum orphan blocks to hold in memory (DoS protection)
const MAX_ORPHAN_BLOCKS: usize = 500;

/// Maximum orphan blocks per peer (prevents single-peer flood)
const MAX_ORPHAN_PER_PEER: usize = 25;
/// Bound on distinct peer_ids tracked in `peer_block_timestamps` before a stale
/// sweep runs, so rotated peer identities can't grow that map without limit.
const MAX_TRACKED_PEERS: usize = 10_000;

/// Maximum age (seconds) before an orphan is evicted.
/// Tightened from 600s to 120s to reduce the selfish mining withholding
/// window. At 10 BPS, 120s = 1200 blocks (vs previous 6000 blocks).
const ORPHAN_EXPIRY_SECS: u64 = 120;

/// P0-C DoS bound: reject an ORPHAN whose UmbraHash epoch is more than this many
/// epochs beyond our best tip's epoch, BEFORE running its PoW. `umbra_check` ->
/// `cache_for_epoch` runs `epoch_seed` (O(epoch) SHA3) + a 16 MiB `mkcache` for
/// the block's epoch; without this bound an attacker floods orphans at an absurd
/// height (near UMBRA_MAX_HEIGHT ~ epoch 333k) to force that work per packet. A
/// real ahead-of-tip relayed block is within a few epochs of the network tip;
/// larger gaps are filled by header-sync (not the bounded orphan buffer), so this
/// never impedes IBD. 1 epoch = EPOCH_BLOCKS (3M) blocks ~ 3.5 days at 10 BPS, so
/// a margin of 2 is hugely generous for near-tip orphans while capping the
/// epoch_seed input to the real chain's epoch, not the attacker's chosen height.
/// Aliased to the single source of truth so the orphan bound and the header-only
/// admission bound can never drift apart (external audit H3).
const MAX_ORPHAN_FUTURE_EPOCHS: u64 =
    crate::engine::mining::algorithms::umbrahash::MAX_FUTURE_EPOCHS;

/// Maximum reorg depth: reject reorgs deeper than this to prevent
/// deep-reorg attacks. Blocks older than this are considered final.
const MAX_REORG_DEPTH: u64 = crate::engine::consensus::reorg::FINALITY_DEPTH;

/// Maximum blocks accepted per peer per minute — a COARSE backstop. DosGuard's
/// per-peer token bucket (100 blk/s) + global cap (200 blk/s) are the real,
/// fine-grained limiters; this only catches pathological cases above them.
///
/// It MUST scale with the block rate. At N BPS the chain itself produces N*60
/// blocks/min, so a peer merely relaying the tip — let alone serving an IBD
/// backfill of thousands of blocks — legitimately sends far more than any fixed
/// small number. The old hardcoded 60/min was BELOW the 10-BPS network rate
/// (600/min): every relaying peer was flagged "exceeds 60 blocks/min", banned,
/// and the chain could never converge (lagging nodes stayed stuck thousands of
/// blocks behind). Set to BPS*60*20 (12,000/min at 10 BPS) — comfortably above
/// both the tip rate and DosGuard's per-peer ceiling, so this never trips on
/// honest traffic while real floods are still bounded by DosGuard + PoW.
const MAX_BLOCKS_PER_PEER_PER_MIN: usize =
    crate::config::consensus::consensus_params::ConsensusParams::BLOCKS_PER_SECOND as usize
        * 60
        * 20;

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
    orphan_pool: Mutex<HashMap<String, (Block, u64, String)>>, // block_hash → (block, timestamp, peer_id)
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
    /// Memoized cumulative proof-of-work per block hash, used for
    /// heaviest-chain fork choice. `cwork(b) = cwork(selected_parent) +
    /// b.header.difficulty`. This is a PURE function of the block's
    /// (immutable) ancestry, so the cache never needs invalidation — a
    /// block's cumulative work is fixed once it exists. Rebuilt lazily after
    /// restart. See `cumulative_work`.
    cwork_cache: Mutex<HashMap<String, u128>>,
    /// Height at which block bodies were last pruned (throttle for maybe_prune).
    last_prune_height: AtomicU64,
}

impl FullNode {
    #[inline]
    fn decode_revert_reason(return_data: &[u8]) -> String {
        const MAX_REVERT_REASON_BYTES: usize = 1024;
        let limited = &return_data[..return_data.len().min(MAX_REVERT_REASON_BYTES)];
        match std::str::from_utf8(limited) {
            Ok(s) => s
                .chars()
                .map(|c| {
                    if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                        '?'
                    } else {
                        c
                    }
                })
                .collect(),
            Err(_) => format!("0x{}", hex::encode(limited)),
        }
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn should_keep_current_tip_on_tie(
        current_best: &str,
        best_tip: &str,
        current_is_tip: bool,
        current_cwork: u128,
        best_cwork: u128,
        current_score: u64,
        best_score: u64,
        current_height: u64,
        best_height: u64,
    ) -> bool {
        !current_best.is_empty()
            && best_tip != current_best
            && current_is_tip
            && current_cwork == best_cwork
            && current_score == best_score
            && current_height == best_height
    }

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

        // ── Seed retarget from the CANONICAL selected-parent chain ──────────
        // Rebuild deterministically from the best tip's selected-parent chain
        // (the same method the runtime reorg path uses), so a freshly-restarted
        // node and a long-running node compute the IDENTICAL difficulty target.
        // (The previous seed replayed get_all_blocks_sorted_by_height — all DAG
        // blocks by height, not the canonical chain — which could diverge.)
        let retarget = match block_store.get_best_hash() {
            Some(best) if !best.is_empty() => {
                let (engine, seeded_diff) =
                    Self::build_retarget_from_canonical(&block_store, &ghostdag, &network, &best);
                set_next_difficulty(seeded_diff);
                slog_info!("node", "retarget_seeded", ema_difficulty => &seeded_diff.to_string());
                engine
            }
            _ => {
                set_next_difficulty(genesis_diff);
                RetargetEngine::new_with_bps(
                    genesis_diff,
                    crate::config::consensus::consensus_params::ConsensusParams::BLOCKS_PER_SECOND,
                )
            }
        };

        // Initialize DAG tips for getblocktemplate — canonical form (sorted,
        // deduped, capped) so select_parent below anchors on the same set a
        // template will use.
        let mut initial_tips = dag_manager.get_tips();
        initial_tips.retain(|h| !h.is_empty());
        initial_tips.sort();
        initial_tips.dedup();
        initial_tips
            .truncate(crate::config::consensus::consensus_params::ConsensusParams::MAX_PARENTS);
        if !initial_tips.is_empty() {
            set_dag_tips(initial_tips.clone());
        }

        // Published next difficulty MUST be anchored on select_parent(the tips a
        // template will use) so miner-stamped == validator-expected (external
        // audit C4). `retarget.ema_difficulty()` is anchored on the single best
        // tip, which differs for a multi-tip reconvergence block. Fall back to the
        // best-tip EMA only when there are no tips yet.
        let seeded_next_diff = {
            let sp = ghostdag.select_parent(&initial_tips);
            if sp.is_empty() {
                retarget.ema_difficulty().max(1)
            } else {
                Self::build_retarget_from_canonical(&block_store, &ghostdag, &network, &sp)
                    .1
                    .max(1)
            }
        };
        set_next_difficulty(seeded_next_diff);

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

        // Build the per-instance mining template cell, seeded consistently with
        // the process-default cell.
        let mining_state = Arc::new(MiningTemplateState::new());
        mining_state.set_next_difficulty(seeded_next_diff);
        if !initial_tips.is_empty() {
            mining_state.set_dag_tips(initial_tips.clone());
        }
        // M5: publish the NEXT block's deferred state commitment anchored on the
        // SAME canonical tips as next_difficulty (miner<->verifier parity). Seed
        // BOTH the per-instance cell AND the process-default cell so the daemon's
        // getblocktemplate (RpcState::mining_state = None) has a value from the
        // very first template — before any block is accepted post-startup — and
        // never emits a null commitment that the M5 verify would reject.
        let initial_psc = expected_prev_state_commitment(&initial_tips, &ghostdag, &block_store);
        mining_state.set_prev_state_commitment(Some(initial_psc.clone()));
        set_prev_state_commitment(Some(initial_psc));

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
            cwork_cache: Mutex::new(HashMap::new()),
            last_prune_height: AtomicU64::new(0),
        }
    }

    /// Prune block bodies far below the tip to bound disk growth. Deletes only
    /// blocks whose height is more than the keep-depth below the best height —
    /// well beyond MAX_REORG_DEPTH (1000) — so no reorg or DAG parent link can
    /// need them; the UTXO set and height/commit indexes are untouched.
    /// Keep-depth defaults to 2000 but is overridable via the env var
    /// SHADOWDAG_PRUNE_KEEP_DEPTH; 0 disables pruning entirely (archival node, so
    /// a far-behind peer can always backfill its missing bodies). Throttled to at
    /// most once per PRUNE_INTERVAL of new height.
    fn maybe_prune(&self) {
        let mut keep_depth: u64 = std::env::var("SHADOWDAG_PRUNE_KEEP_DEPTH")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(2_000);
        if keep_depth == 0 {
            return;
        }
        // CONSENSUS-CRITICAL GUARD (external audit M1): block BODIES within the
        // reorg and difficulty windows below the tip MUST stay resident — the
        // ancestry-pure difficulty walk (SHORT_WINDOW blocks) and the reorg
        // fork-point walk (MAX_REORG_DEPTH) both read them via block_store.
        // get_block. A too-small keep_depth prunes a body inside a window, so the
        // walk stops early and this node computes a DIFFERENT next_diff / fork
        // point than an un-pruned node — which the strict-equality difficulty
        // check turns into a consensus split. Clamp any positive keep_depth up to
        // that window floor (archival keep_depth=0 is untouched above).
        let min_keep = (SHORT_WINDOW as u64).max(MAX_REORG_DEPTH);
        if keep_depth < min_keep {
            slog_warn!("pruning", "keep_depth_clamped_to_window_floor",
                requested => keep_depth, floor => min_keep);
            keep_depth = min_keep;
        }
        const PRUNE_INTERVAL: u64 = 500;
        let best = match self
            .block_store
            .get_best_hash()
            .and_then(|h| self.block_store.get_block(&h))
        {
            Some(b) => b.header.height,
            None => return,
        };
        if best <= keep_depth {
            return;
        }
        let last = self.last_prune_height.load(Ordering::Relaxed);
        if best < last.saturating_add(PRUNE_INTERVAL) {
            return;
        }
        self.last_prune_height.store(best, Ordering::Relaxed);
        let cutoff = best - keep_depth;
        let pruned = self.block_store.prune_blocks_below_height(cutoff);
        if pruned > 0 {
            slog_warn!("pruning", "pruned_old_block_bodies",
                count => pruned, below_height => cutoff, best_height => best);
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
        // Known block relay is idempotent; do not spend DoS/rate budget on it.
        if self.dag_manager.block_exists(&block.header.hash)
            || self.block_store.get_block(&block.header.hash).is_some()
        {
            return Err(NodeError::BlockRejected("already exists".to_string()));
        }

        // ── L0: Per-peer DoS guard (cheapest — no deserialization) ────
        // canonical_size_estimate is an approximation (header + tx_count * avg_tx_size).
        // The exact check_block_size (below) uses the real serialized size limit.
        // This estimate is a cheap pre-filter that rejects obviously oversized blocks
        // before the more expensive serialization-based check.
        let block_size_estimate = block.canonical_size_estimate();
        match self
            .dos_guard
            .check(peer_id, &MsgType::Block, block_size_estimate)
        {
            DosVerdict::Allow => {}
            DosVerdict::BanActive => {
                return Err(NodeError::PeerBanned {
                    peer: peer_id.to_string(),
                    reason: "peer is banned".to_string(),
                });
            }
            verdict => {
                return Err(NodeError::PeerBanned {
                    peer: peer_id.to_string(),
                    reason: format!("DOS_REJECTED: {:?}", verdict),
                });
            }
        }

        // ── L0.5: Per-peer rate limiting ─────────────────────────────
        // Keep this before full serialization so high-rate spam is rejected
        // with minimal CPU cost.

        if self.is_peer_rate_limited(peer_id) {
            return Err(NodeError::PeerBanned {
                peer: peer_id.to_string(),
                reason: format!(
                    "RATE_LIMITED: exceeds {} blocks/min",
                    MAX_BLOCKS_PER_PEER_PER_MIN
                ),
            });
        }

        // ── L0.25: Exact serialized size check ────────────────────────
        // DosGuard::check uses canonical_size_estimate which under-counts.
        // Serialize once and enforce the exact byte-size limit.
        let exact_block_size = bincode::serialize(block)
            .map(|bytes| bytes.len())
            .map_err(|e| {
                NodeError::BlockRejected(format!("failed to serialize block for size check: {}", e))
            })?;
        if let Err(e) = self.dos_guard.check_block_size(exact_block_size) {
            return Err(NodeError::PeerBanned {
                peer: peer_id.to_string(),
                reason: format!("BLOCK_TOO_LARGE: {}", e),
            });
        }

        // ── L1 → L2 → L3 → DAG → L4 ────────────────────────────────
        let r = self.process_block_inner(block, peer_id);
        if r.is_ok() {
            self.maybe_prune();
        }
        r
    }

    /// Process a block (internal use, no peer tracking).
    pub fn process_block(&self, block: &Block) -> Result<(), NodeError> {
        let r = self.process_block_inner(block, "local");
        if r.is_ok() {
            self.maybe_prune();
        }
        r
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
        use std::collections::{HashSet, VecDeque};

        const TARGET_ANCESTOR_COUNT: usize = 32; // Collect up to 32 ancestors
        const MAX_WALK_DEPTH: usize = 16; // Walk up to 16 DAG levels (>= MEDIAN_TIME_SPAN=11 + headroom for DAG branching)

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

    /// Expected difficulty for validating an incoming block.
    ///
    /// Why this exists:
    /// - `retarget.ema_difficulty()` represents the *next* difficulty from the
    ///   current selected tip.
    /// - Competing blocks at the same height can arrive after tip advanced.
    ///   Those blocks should still be checked against that height's difficulty,
    ///   not against the next-height value.
    fn expected_difficulty_for_block(&self, block: &Block) -> Result<u64, NodeError> {
        // Genesis keeps its own configured difficulty.
        if block.header.height == 0 {
            return Ok(block.header.difficulty.max(1));
        }

        // CONSENSUS-CRITICAL (external audit C4): the expected difficulty MUST be
        // a PURE function of the CANDIDATE's own ancestry — never the local node's
        // tip or its inventory of same-height side blocks. The previous code
        // anchored on get_block_hashes_at_height (the LOCAL set of blocks at that
        // height) for height <= best, and on the LOCAL tip's retarget EMA for a
        // tip extension. Two nodes with different side-block inventories / tips
        // could then accept vs reject the SAME block → a consensus split.
        //
        // Anchor instead on the CANONICAL selected parent — GHOSTDAG's
        // deterministic pick among the block's committed parents (NOT the
        // untrusted header.selected_parent, which like blue_score is not covered
        // by PoW) — and rebuild the retarget from THAT ancestry window. The next
        // difficulty after the selected parent is exactly what the miner stamped
        // (get_next_difficulty == build_retarget_from_canonical of the tip it
        // extended == this selected parent), so it is identical on every node and
        // independent of local state.
        let selected_parent = self.ghostdag.select_parent(&block.header.parents);
        if selected_parent.is_empty() {
            return Err(NodeError::BlockRejected(format!(
                "cannot compute expected difficulty at height {}: no canonical selected parent",
                block.header.height
            )));
        }
        Ok(self.expected_difficulty_for_selected_parent(&selected_parent))
    }

    /// The difficulty a block whose canonical selected parent is `selected_parent`
    /// MUST carry — a pure function of that selected-parent chain (external audit
    /// C4). This is the SINGLE source of truth shared by the validator
    /// (`expected_difficulty_for_block`) and the miner-template publisher, so the
    /// miner stamps EXACTLY what the validator recomputes. Both derive the anchor
    /// via `ghostdag.select_parent` on their parent set (the block's committed
    /// parents vs the current tips) — a previous version stamped from a DIFFERENT
    /// anchor (`select_best_tip`: cumulative_work-first, opposite hash tie-break),
    /// so a reconvergence block merging sibling tips was stamped f(A) but validated
    /// against f(B) and universally rejected, halting production.
    fn expected_difficulty_for_selected_parent(&self, selected_parent: &str) -> u64 {
        let (_engine, expected) = Self::build_retarget_from_canonical(
            &self.block_store,
            &self.ghostdag,
            &self.network,
            selected_parent,
        );
        expected.max(1)
    }

    fn process_block_inner(&self, block: &Block, peer_id: &str) -> Result<(), NodeError> {
        // Fast duplicate guard before dynamic difficulty checks.
        if self.dag_manager.block_exists(&block.header.hash)
            || self.block_store.get_block(&block.header.hash).is_some()
        {
            return Err(NodeError::BlockRejected("already exists".to_string()));
        }

        // ═══════════════════════════════════════════════════════════════
        // CONSENSUS-CRITICAL VALIDATION PIPELINE
        //
        //   0. PARENT EXISTENCE (cheap DB read). Decides orphan vs connectable.
        //      An ORPHAN gets SELF-CONSISTENT validation only (L1 + PoW) and is
        //      buffered — ancestry-dependent checks are DEFERRED (see W4 below).
        //   1. FULL validation for a connectable block: L1 → PoW → L2 (merkle,
        //      timestamps, signatures) → L3 (difficulty, checkpoints, coinbase).
        //      Now safe because the parents (hence the difficulty window and MTP
        //      ancestors) are present.
        //   2. PERSIST + DAG/GHOSTDAG insertion (block_store, dag_manager).
        //   3. UTXO EXECUTION in GHOSTDAG order (recompute_virtual_chain),
        //      sequential, atomic rollback on failure.
        //
        // SECURITY: an orphan is buffered only after PoW passes (bounds the
        // cost — no work-free orphan flood), and it is NEVER applied until it
        // reconnects and passes the FULL validation. So every ancestry-
        // dependent rule (difficulty, MTP) is still enforced before apply —
        // only its timing moves to reconnect. This is what lets a far-behind
        // node accept ahead-of-tip blocks instead of hard-rejecting valid ones
        // on a difficulty computed from its own un-synced tip.
        // ═══════════════════════════════════════════════════════════════

        // ─── PARENT-EXISTENCE FIRST (W4) ─────────────────────────────────
        // Ancestry-dependent validation (difficulty, MTP timestamps) requires
        // the block's parents. For an ORPHAN (parents not yet present) we
        // CANNOT compute the expected difficulty — computing it against our own
        // un-synced tip spuriously mismatches and hard-rejects a perfectly
        // valid ahead-of-tip block, which is exactly what stops a far-behind
        // node from ever catching up. So: validate only the SELF-CONSISTENT
        // checks (structure + PoW — enough to reject junk and bound cost), then
        // buffer the orphan. Its FULL ancestry-dependent validation (difficulty
        // etc.) runs when it reconnects — before it is ever applied — so the
        // security guarantee is preserved, only deferred.
        match BlockValidator::validate_parents_exist(block, &self.block_store, &self.dag_manager) {
            Ok(()) => {}
            Err(e) if e.to_string().contains("not found") => {
                // P0-C: cheap tip-relative epoch bound BEFORE running UmbraHash
                // PoW on this UNVALIDATED orphan. validate_self_consistent ->
                // umbra_check -> cache_for_epoch runs epoch_seed (O(epoch) SHA3)
                // + a 16 MiB mkcache for the block's epoch; reject an absurd-
                // height flood packet here without touching that work. Real
                // ahead-of-tip blocks are within MAX_ORPHAN_FUTURE_EPOCHS of the
                // tip; larger gaps are filled by header-sync, not this buffer.
                if self.orphan_epoch_too_far(block.header.height) {
                    return Err(NodeError::BlockRejected(format!(
                        "ORPHAN height {} epoch too far beyond tip (umbra pre-cache DoS bound)",
                        block.header.height
                    )));
                }
                if let Err(reason) =
                    BlockValidator::validate_self_consistent(block, &self.network)
                {
                    return Err(NodeError::BlockRejected(format!(
                        "Block validation failed: {}",
                        reason
                    )));
                }
                self.add_orphan(block.clone(), peer_id);
                return Err(NodeError::BlockRejected(format!("ORPHAN: {}", e)));
            }
            Err(e) => {
                return Err(NodeError::BlockRejected(format!(
                    "Parent validation failed: {}",
                    e
                )))
            }
        }

        // Parents are present → FULL validation, incl. ancestry-dependent
        // difficulty (computed from the now-available parent window) and
        // timestamps. A block that reaches here is fully connectable.
        let expected_diff = Some(self.expected_difficulty_for_block(block)?);
        let ancestor_ts = self.collect_ancestor_timestamps(block);
        let result = BlockValidator::validate_block_full_with_difficulty(
            block,
            &self.utxo_set,
            &ancestor_ts,
            &self.network,
            expected_diff,
        );
        if !result.valid {
            return Err(NodeError::BlockRejected(format!(
                "Block validation failed: {}",
                result.reason.unwrap_or_else(|| "unknown".to_string())
            )));
        }

        // M5 DEFERRED-VERIFY: the block's prev_state_commitment MUST equal the
        // value derived from its SELECTED PARENT's IDENTITY via the SAME shared fn
        // the template publisher used (parents are present + in GHOSTDAG here, so
        // select_parent is defined). NOTE: this does NOT verify the parent's
        // post-execution roots — they are not bound; see
        // expected_prev_state_commitment. PoW already binds the committed value
        // into the hash (a tampered value fails PoW); this check additionally
        // rejects a self-consistent block that committed to the WRONG parent.
        // Non-genesis only (genesis carries its own constant).
        if block.header.height > 0 {
            let expected = expected_prev_state_commitment(
                &block.header.parents,
                &self.ghostdag,
                &self.block_store,
            );
            if block.header.prev_state_commitment.as_deref() != Some(expected.as_str()) {
                return Err(NodeError::BlockRejected(format!(
                    "prev_state_commitment mismatch: header={:?} expected={}",
                    block.header.prev_state_commitment, expected
                )));
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // PHASE 2: PERSIST THEN ACCEPT INTO DAG (no UTXO — structure only)
        //
        // BlockStore is the source of truth. Persist FIRST so that if
        // the node crashes after save but before DAG insertion, recovery
        // can rebuild the DAG from BlockStore. If save fails, we must
        // NOT insert into the DAG (no topology without data).
        // ═══════════════════════════════════════════════════════════════

        if !self.save_block_normalized(block) {
            return Err(NodeError::BlockRejected(format!(
                "BlockStore save failed for {} — refusing to add to DAG without persistence",
                &block.header.hash
            )));
        }

        if let Err(e) = self.dag_manager.add_block_validated(block, true) {
            // Clean up persisted block — DAG rejected it, so it must not remain in BlockStore
            let _ = self.block_store.delete_block(&block.header.hash);
            return Err(NodeError::BlockRejected(format!(
                "DAG insertion failed: {}",
                e
            )));
        }

        let dag_block = DagBlock {
            hash: block.header.hash.clone(),
            parents: block.header.parents.clone(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        if let Err(e) = self.ghostdag.add_block(dag_block) {
            // Roll back DAG topology + BlockStore so no stale topology remains.
            if let Err(re) = self.dag_manager.remove_block_topology(&block.header.hash) {
                slog_error!("node", "dag_topology_rollback_failed",
                    hash => &block.header.hash, error => &re.to_string());
            }
            let _ = self.block_store.delete_block(&block.header.hash);
            slog_error!("node", "ghostdag_add_failed_cleanup",
                hash => &block.header.hash, error => &e.to_string());
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
            // M3 (atomic acceptance): the just-added block is a CHILDLESS tip, and
            // recompute_virtual_chain restores the UTXO set to the pre-insert
            // (old-chain) state on a non-fatal Err. Remove the block from GHOSTDAG
            // + DAG topology + BlockStore so acceptance is all-or-nothing —
            // otherwise a phantom GHOSTDAG tip (metadata present, body deleted)
            // could be re-selected as best_tip and roll back the real chain while
            // applying nothing.
            slog_error!("node", "virtual_chain_recompute_failed_after_insert",
                hash => &block.header.hash, error => &e.to_string());
            self.drop_offending_block_if_leaf(&block.header.hash);
            return Err(e);
        }

        self.process_orphans_of(&block.header.hash);

        Ok(())
    }

    /// Same as process_block_inner but WITHOUT triggering orphan processing.
    /// Used by the iterative orphan resolver to avoid recursion.
    fn process_block_without_orphans(&self, block: &Block) -> Result<(), NodeError> {
        // Keep duplicate handling consistent with process_block_inner().
        if self.dag_manager.block_exists(&block.header.hash)
            || self.block_store.get_block(&block.header.hash).is_some()
        {
            return Err(NodeError::BlockRejected("already exists".to_string()));
        }

        // Parent-existence FIRST (W4): ancestry-dependent validation
        // (difficulty, MTP) needs the parents. This is the orphan-REPROCESS
        // path; if a parent is still missing (e.g. a deeper ancestor hasn't
        // arrived), fail WITHOUT the spurious difficulty check and WITHOUT
        // re-buffering (the caller manages the orphan pool; this variant must
        // not recurse into orphan handling). Only self-consistent checks would
        // apply to a still-orphan, and it's already buffered, so just return.
        if let Err(e) =
            BlockValidator::validate_parents_exist(block, &self.block_store, &self.dag_manager)
        {
            return Err(NodeError::BlockRejected(e.to_string()));
        }

        // Parents present → full ancestry-dependent validation.
        let expected_diff = Some(self.expected_difficulty_for_block(block)?);
        let ancestor_ts = self.collect_ancestor_timestamps(block);
        let result = BlockValidator::validate_block_full_with_difficulty(
            block,
            &self.utxo_set,
            &ancestor_ts,
            &self.network,
            expected_diff,
        );
        if !result.valid {
            return Err(NodeError::BlockRejected(
                result.reason.unwrap_or_else(|| "unknown".to_string()),
            ));
        }

        // M5 DEFERRED-VERIFY (orphan-reconnect path): identical to the check in
        // process_block_inner. This path is drained by the orphan resolver and is
        // the normal IBD reconnection route, so the M5 commitment MUST be enforced
        // here too — otherwise enforcement would be arrival-order-dependent (a
        // block that arrives as an orphan and is later reconnected would skip the
        // check), an attacker-controllable consensus split. Non-genesis only.
        if block.header.height > 0 {
            let expected = expected_prev_state_commitment(
                &block.header.parents,
                &self.ghostdag,
                &self.block_store,
            );
            if block.header.prev_state_commitment.as_deref() != Some(expected.as_str()) {
                return Err(NodeError::BlockRejected(format!(
                    "prev_state_commitment mismatch: header={:?} expected={}",
                    block.header.prev_state_commitment, expected
                )));
            }
        }

        if !self.save_block_normalized(block) {
            return Err(NodeError::BlockRejected(format!(
                "BlockStore save failed for {} — refusing to add to DAG without persistence",
                &block.header.hash
            )));
        }

        if let Err(e) = self.dag_manager.add_block_validated(block, true) {
            // Clean up persisted block — DAG rejected it, so it must not remain in BlockStore
            let _ = self.block_store.delete_block(&block.header.hash);
            return Err(NodeError::BlockRejected(format!(
                "DAG insertion failed: {}",
                e
            )));
        }

        let dag_block = DagBlock {
            hash: block.header.hash.clone(),
            parents: block.header.parents.clone(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        if let Err(e) = self.ghostdag.add_block(dag_block) {
            if let Err(re) = self.dag_manager.remove_block_topology(&block.header.hash) {
                slog_error!("node", "dag_topology_rollback_failed",
                    hash => &block.header.hash, error => &re.to_string());
            }
            let _ = self.block_store.delete_block(&block.header.hash);
            slog_error!("node", "ghostdag_add_failed_cleanup",
                hash => &block.header.hash, error => &e.to_string());
            return Err(NodeError::BlockRejected(format!("GHOSTDAG: {}", e)));
        }

        if let Err(e) = self.recompute_virtual_chain() {
            // M3 (atomic acceptance): the just-added block is a CHILDLESS tip, and
            // recompute_virtual_chain restores the UTXO set to the pre-insert
            // (old-chain) state on a non-fatal Err. Remove the block from GHOSTDAG
            // + DAG topology + BlockStore so acceptance is all-or-nothing —
            // otherwise a phantom GHOSTDAG tip (metadata present, body deleted)
            // could be re-selected as best_tip and roll back the real chain while
            // applying nothing.
            slog_error!("node", "virtual_chain_recompute_failed_after_insert",
                hash => &block.header.hash, error => &e.to_string());
            self.drop_offending_block_if_leaf(&block.header.hash);
            return Err(e);
        }
        Ok(())
    }

    /// Select the best tip from a set of DAG tips using the canonical rule:
    ///   highest blue_score -> highest chain_height -> lowest hash (deterministic)
    ///
    /// This MUST be used everywhere a "best tip" is chosen (runtime AND recovery)
    /// to guarantee consistent fork-choice across restarts.
    /// Cumulative proof-of-work for `hash`: the sum of `header.difficulty` over
    /// the selected-parent chain back to genesis. Memoized in `cwork_cache`.
    ///
    /// This is a deterministic pure function of the block's immutable ancestry
    /// (selected_parent + the consensus-enforced per-block difficulty), so the
    /// memo is always valid and identical on every node — no invalidation on
    /// reorg, and a restarted node rebuilds the same values. The walk is
    /// iterative (no recursion) to stay safe on very long chains, and stops at
    /// the first already-cached ancestor for amortized O(1) cost.
    pub fn cumulative_work(&self, hash: &str) -> u128 {
        if hash.is_empty() {
            return 0;
        }
        let mut cache = self.cwork_cache.lock().unwrap_or_else(|e| e.into_inner());
        Self::cumulative_work_inner(&self.block_store, &mut cache, hash)
    }

    /// Core of [`cumulative_work`], parameterized over the store + memo cache so
    /// it can be unit-tested without a full node. Walks the selected-parent
    /// chain (iteratively) to genesis or the first cached ancestor, then
    /// accumulates `header.difficulty` upward. Pure function of the chain.
    fn cumulative_work_inner(
        block_store: &BlockStore,
        cache: &mut HashMap<String, u128>,
        hash: &str,
    ) -> u128 {
        if hash.is_empty() {
            return 0;
        }
        if let Some(&w) = cache.get(hash) {
            return w;
        }
        // Walk down to genesis or the first cached ancestor, collecting
        // (hash, difficulty) so we can accumulate upward afterwards.
        let mut pending: Vec<(String, u128)> = Vec::new();
        let mut cursor = hash.to_string();
        let mut base: u128 = 0;
        loop {
            if cursor.is_empty() {
                break;
            }
            if let Some(&w) = cache.get(&cursor) {
                base = w;
                break;
            }
            match block_store.get_block(&cursor) {
                Some(b) => {
                    pending.push((cursor.clone(), b.header.difficulty as u128));
                    // resolved_selected_parent: stored blocks may carry None
                    // (submitblock), which would truncate the work sum to one
                    // block and cripple fork choice.
                    cursor = b.header.resolved_selected_parent().unwrap_or_default();
                }
                None => break, // missing ancestor: treat as chain base
            }
        }
        // Accumulate from the oldest pending block (last pushed) upward.
        let mut acc = base;
        while let Some((h, diff)) = pending.pop() {
            acc = acc.saturating_add(diff);
            cache.insert(h, acc);
        }
        cache.get(hash).copied().unwrap_or(base)
    }

    /// Persist a block with its canonical GHOSTDAG selected parent filled in.
    ///
    /// submitblock stores blocks with `selected_parent=None` by design (client
    /// input is untrusted) and gossiped blocks may carry a stale/foreign value,
    /// so the node must set it. The CANONICAL value is GHOSTDAG's selected
    /// parent — argmax over the parents of (blue_score, chain_height, hash) via
    /// `GhostDag::select_parent` — NOT `parents[0]`. On a multi-parent block
    /// those differ, and the header's selected parent feeds the consensus walks
    /// (cumulative work / fork choice, difficulty retarget, reorg fork-point,
    /// undo pruning, recovery replay). Storing GHOSTDAG's value makes the
    /// header agree EXACTLY with what `ghostdag.add_block` computes and stores
    /// internally for this block, so every walk follows the true blue chain.
    ///
    /// The parents' blue scores are already known here (parents were accepted
    /// earlier), so this is computable before THIS block enters GHOSTDAG.
    /// Hash-safe: the PoW preimage covers `parents`, not `selected_parent`.
    /// Genesis (no parents) stores None, which terminates the walks.
    fn save_block_normalized(&self, block: &Block) -> bool {
        let canonical = if block.header.parents.is_empty() {
            None
        } else {
            Some(self.ghostdag.select_parent(&block.header.parents))
        };
        if block.header.selected_parent == canonical {
            return self.block_store.save_block(block);
        }
        let mut normalized = block.clone();
        normalized.header.selected_parent = canonical;
        self.block_store.save_block(&normalized)
    }

    /// Select the best tip by HEAVIEST CUMULATIVE WORK (Nakamoto/Kaspa rule),
    /// then blue_score, then chain_height, then lowest hash as deterministic
    /// tie-breaks. Ranking by total work — not by blue block COUNT — prevents a
    /// competing chain with more blocks but less proof-of-work from displacing
    /// the honest heaviest chain.
    pub fn select_best_tip(&self, tips: &[String]) -> Option<String> {
        let mut cache = self.cwork_cache.lock().unwrap_or_else(|e| e.into_inner());
        Self::select_best_tip_inner(&self.block_store, &self.ghostdag, &mut cache, tips)
    }

    /// Static core of [`select_best_tip`], shared by the runtime path and the
    /// crash-recovery path (daemon) so BOTH agree on fork choice exactly — a
    /// mismatch would let a node pick a different canonical tip after restart.
    pub fn select_best_tip_inner(
        block_store: &BlockStore,
        ghostdag: &GhostDag,
        cache: &mut HashMap<String, u128>,
        tips: &[String],
    ) -> Option<String> {
        tips.iter()
            .max_by(|a, b| {
                Self::cumulative_work_inner(block_store, cache, a)
                    .cmp(&Self::cumulative_work_inner(block_store, cache, b))
                    .then_with(|| ghostdag.get_blue_score(a).cmp(&ghostdag.get_blue_score(b)))
                    .then_with(|| {
                        ghostdag
                            .get_chain_height(a)
                            .cmp(&ghostdag.get_chain_height(b))
                    })
                    .then_with(|| b.cmp(a)) // lower hash wins
            })
            .cloned()
    }

    /// Recompute the virtual selected parent chain after DAG changes.
    ///
    /// Walks the GHOSTDAG ordering to determine which blocks should
    /// Build a fresh `RetargetEngine` purely from the CANONICAL selected-parent
    /// chain ending at `best_tip` (last `SHORT_WINDOW` blocks, oldest→newest),
    /// returning it with the resulting next difficulty. Difficulty is thus a pure
    /// function of the canonical chain — NOT of reorg/arrival history — so every
    /// node computes the same value (eliminates cross-node difficulty divergence
    /// after reorgs, which the strict-equality difficulty check would otherwise
    /// turn into a chain split).
    fn build_retarget_from_canonical(
        block_store: &BlockStore,
        ghostdag: &GhostDag,
        network: &NetworkMode,
        best_tip: &str,
    ) -> (RetargetEngine, u64) {
        let genesis_diff = crate::config::genesis::genesis::genesis_difficulty_for(network);
        let mut engine = RetargetEngine::new_with_bps(
            genesis_diff,
            crate::config::consensus::consensus_params::ConsensusParams::BLOCKS_PER_SECOND,
        );
        // Walk the canonical selected-parent chain newest→oldest (≤ SHORT_WINDOW).
        let mut chain: Vec<crate::domain::block::block::Block> = Vec::new();
        let mut cursor = best_tip.to_string();
        while chain.len() < SHORT_WINDOW && !cursor.is_empty() {
            match block_store.get_block(&cursor) {
                Some(b) => {
                    let parent = b.header.resolved_selected_parent().unwrap_or_default();
                    chain.push(b);
                    cursor = parent;
                }
                None => break,
            }
        }
        chain.reverse(); // oldest → newest
        let mut next_diff = genesis_diff;
        for b in &chain {
            // CONSENSUS-CRITICAL: the per-block DAG-rate weight MUST be a
            // deterministic function of the block itself, identical on every
            // node regardless of which side/red blocks it happens to hold.
            // `blocks_at_height` counts blocks in the LOCAL store at this
            // height, which differs between a full miner (holds all siblings)
            // and a syncing follower (holds only the selected chain) — so the
            // two computed DIFFERENT next-block difficulties for the same
            // canonical tip and the follower rejected the miner's block forever
            // ("difficulty mismatch"), stalling IBD. `parents.len()` is committed
            // in the header and covered by PoW (see
            // BlockHeader::resolved_selected_parent), so it is identical on all
            // nodes and still scales with merge width (a block merging W tips
            // contributes W), preserving the DAG-rate correction while making it
            // deterministic across sync states.
            let dag_width = (b.header.parents.len() as u64).max(1);
            // CONSENSUS-CRITICAL (external audit C3): use the GHOSTDAG-derived
            // canonical blue score, NOT `b.header.blue_score`. The header
            // blue_score field is NOT covered by the PoW pre-image (the miner
            // stamps it but it is not hashed), so a peer can mutate it on the wire
            // without re-mining; feeding it into the retarget would make two nodes
            // compute DIFFERENT next-difficulties from the same block hash → a
            // consensus split. GHOSTDAG recomputes the blue score deterministically
            // from the block's committed ancestry, so it is identical on every node.
            let canonical_blue = ghostdag.get_blue_score(&b.header.hash);
            next_diff = engine.on_new_block(BlockTimeRecord {
                height: b.header.height,
                timestamp: b.header.timestamp,
                difficulty: b.header.difficulty,
                dag_block_count: dag_width,
                blue_score: canonical_blue,
            });
        }
        (engine, next_diff)
    }

    /// have their transactions executed, and in what order.
    ///
    /// If the selected chain changed (reorg), rolls back old blocks
    /// and applies new ones — all in GHOSTDAG order.
    /// M3 (atomic acceptance): drop an offending block from GHOSTDAG + DAG
    /// topology + BlockStore, but ONLY when it is a CHILDLESS leaf
    /// (`ghostdag.remove_block` succeeds). A mid-reorg-chain non-leaf block is
    /// left FULLY intact — deleting only its body (as an unconditional
    /// `delete_block` would) leaves it un-resyncable (the dedup gate still sees
    /// it in the DAG) and silently skipped on the next recompute (body gone),
    /// which is strictly worse than keeping the re-appliable block. The
    /// just-added-tip acceptance paths always hit the leaf case; the reorg-apply
    /// failure paths may not, so this guard is what keeps store/DAG/ghostdag
    /// mutually consistent. Returns true iff the block was removed.
    fn drop_offending_block_if_leaf(&self, block_hash: &str) -> bool {
        match self.ghostdag.remove_block(block_hash) {
            Ok(()) => {
                let _ = self.dag_manager.remove_block_topology(block_hash);
                let _ = self.block_store.delete_block(block_hash);
                true
            }
            Err(re) => {
                slog_warn!("node", "offending_block_kept_non_leaf",
                    block => block_hash, error => &re.to_string());
                false
            }
        }
    }

    pub fn recompute_virtual_chain(&self) -> Result<(), NodeError> {
        // Get the new best tip from GHOSTDAG
        let tips = self.ghostdag.get_tips();
        if tips.is_empty() {
            return Ok(());
        }

        // Canonical tip selection: cumulative work -> blue_score -> height -> hash
        let mut best_tip = match self.select_best_tip(&tips) {
            Some(tip) => tip,
            None => return Ok(()),
        };

        let current_best = self.block_store.get_best_hash().unwrap_or_default();

        // Reorg stability guard:
        // If the current best is still a DAG tip and has the SAME quality as the
        // newly selected tip (equal cumulative work, blue_score AND chain_height),
        // keep the current best to avoid tie-flip oscillation and needless
        // rollback/apply churn. Cumulative work must match too, or a heavier
        // competing tip could be wrongly held off by an equal-score lighter one.
        let current_is_tip = tips.iter().any(|t| t == &current_best);
        let best_cwork = self.cumulative_work(&best_tip);
        let current_cwork = self.cumulative_work(&current_best);
        let best_score = self.ghostdag.get_blue_score(&best_tip);
        let best_height = self.ghostdag.get_chain_height(&best_tip);
        let current_score = self.ghostdag.get_blue_score(&current_best);
        let current_height = self.ghostdag.get_chain_height(&current_best);
        if Self::should_keep_current_tip_on_tie(
            &current_best,
            &best_tip,
            current_is_tip,
            current_cwork,
            best_cwork,
            current_score,
            best_score,
            current_height,
            best_height,
        ) {
            best_tip = current_best.clone();
        }

        if best_tip == current_best {
            return Ok(()); // No chain change
        }

        // Build the selected parent chain from new tip back to the true fork
        // point with the old chain. Walk both chains (new tip and current best)
        // back via selected_parent to find where they diverge.
        use std::collections::HashSet;

        // First, collect the old chain's selected-parent ancestry.
        // resolved_selected_parent throughout these walks: stored blocks may
        // carry selected_parent=None (submitblock path), which made every walk
        // stop after one hop — fork_point became the new tip itself, so EVERY
        // insert rolled back the current tip and applied only the new block,
        // leaving the UTXO set holding just the newest coinbases.
        let mut old_chain_set = HashSet::new();
        {
            let mut cursor = current_best.clone();
            // Bound the ancestry walk to the reorg window. A fork point deeper
            // than MAX_REORG_DEPTH is rejected as a too-deep reorg below, so
            // collecting the old chain past that depth is wasted I/O — and
            // walking all the way to genesis made EVERY block apply
            // O(chain-length) block reads, which is the IBD apply-rate ceiling
            // (a follower at height H re-reads ~H blocks per block it applies).
            // Bounding to MAX_REORG_DEPTH is semantics-preserving: the
            // accept/reject/apply/rollback decision is unchanged because any
            // reorg whose fork lies beyond this depth is rejected regardless.
            let mut depth = 0u64;
            while !cursor.is_empty() && depth <= MAX_REORG_DEPTH {
                old_chain_set.insert(cursor.clone());
                cursor = self
                    .block_store
                    .get_block(&cursor)
                    .and_then(|b| b.header.resolved_selected_parent())
                    .unwrap_or_default();
                depth += 1;
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

            // Bound symmetrically: if the new chain has not met the old chain
            // within the reorg window, this is a too-deep reorg. Stop and let
            // the MAX_REORG_DEPTH check below reject it, instead of walking to
            // genesis (an O(chain-length) walk an attacker could otherwise
            // force with a single deep side-chain block).
            if new_chain.len() as u64 > MAX_REORG_DEPTH {
                break;
            }

            // Walk to selected parent
            match self.block_store.get_block(&cursor) {
                Some(b) => {
                    match b.header.resolved_selected_parent() {
                        Some(sp) => cursor = sp,
                        None => break, // Genesis
                    }
                }
                None => break,
            }
        }

        // `cursor` now holds the fork point — the first block common to both chains.
        let fork_point = cursor.clone();

        // Reverse so we apply from oldest to newest (GHOSTDAG order)
        new_chain.reverse();

        // ── DEEP REORG PROTECTION ──────────────────────────────────────
        // Reject reorgs deeper than MAX_REORG_DEPTH. Blocks older than
        // this are considered final. This prevents an attacker from
        // secretly building a long side-chain and causing a massive reorg.
        if new_chain.len() as u64 > MAX_REORG_DEPTH {
            return Err(NodeError::BlockRejected(format!(
                "reorg depth {} exceeds MAX_REORG_DEPTH {}",
                new_chain.len(),
                MAX_REORG_DEPTH
            )));
        }
        // Preflight old-chain rollback depth BEFORE any rollback writes.
        // Without this pre-check, a deep reorg can trigger partial rollback
        // and then fail mid-way, leaving state inconsistent.
        if !current_best.is_empty() && !new_chain.contains(&current_best) {
            let mut cursor = current_best.clone();
            let mut projected_rollback_depth = 0u64;
            while !cursor.is_empty() && cursor != fork_point {
                projected_rollback_depth = projected_rollback_depth.saturating_add(1);
                if projected_rollback_depth > MAX_REORG_DEPTH {
                    return Err(NodeError::BlockRejected(format!(
                        "reorg rollback depth {} exceeds MAX_REORG_DEPTH {}",
                        projected_rollback_depth, MAX_REORG_DEPTH
                    )));
                }
                cursor = self
                    .block_store
                    .get_block(&cursor)
                    .and_then(|b| b.header.resolved_selected_parent())
                    .unwrap_or_default();
            }
        }

        // Rollback entire old chain from current_best back to fork point
        let mut rolled_back_old: Vec<String> = Vec::new();
        if !current_best.is_empty() && !new_chain.contains(&current_best) {
            let mut cursor = current_best.clone();
            let mut rollback_count = 0u64;
            while !cursor.is_empty() && cursor != fork_point {
                self.utxo_set.rollback_block_undo(&cursor).map_err(|e| {
                    slog_error!("node", "rollback_failed", block => &cursor, error => &format!("{}", e));
                    NodeError::BlockRejected(format!("rollback failed for {}: {}", cursor, e))
                })?;
                // Contract state rollback + receipt purge.
                self.rollback_contract_block(&cursor)?;
                rolled_back_old.push(cursor.clone());
                rollback_count += 1;
                // Walk to parent via selected_parent
                cursor = self
                    .block_store
                    .get_block(&cursor)
                    .and_then(|b| b.header.resolved_selected_parent())
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
            // Skip only if BOTH the UTXO state (utxo:commitment) AND the contract
            // state (contract:applied marker) for this block are persisted. UTXO
            // and contract state live in SEPARATE RocksDBs committed in separate
            // batches; a crash between them leaves the UTXO commitment present but
            // the contract state missing. Keying the skip off UTXO commitment
            // alone would permanently skip such a block, leaving a contract-state
            // hole (state_root divergence). Requiring the contract marker too
            // forces re-execution of a crash-interrupted block.
            if self.utxo_set.get_commitment(block_hash).is_some()
                && self.contract_storage.contract_block_applied(block_hash)
            {
                continue;
            }

            // Partially-applied block (UTXO commitment present, contract marker
            // missing — e.g. a crash between the two DBs, or a recovery replay
            // that rewrote UTXO state without contract markers): re-execution
            // MUST start from a clean slate. Otherwise apply_block_dag_ordered
            // DUP-skips the block's OWN transactions (their tx_seen markers
            // already exist), returning applied_fees=0 — and the post-execution
            // coinbase check then rejects a perfectly valid block by exactly
            // its fee sum, which at boot is fatal (permanent crash loop). The
            // stored undo data (written by every apply path) makes the
            // rollback+reapply sequence idempotent.
            if self.utxo_set.get_commitment(block_hash).is_some() {
                if let Err(e) = self.utxo_set.rollback_block_undo(block_hash) {
                    slog_warn!("node", "partial_block_rollback_before_reapply_failed",
                        block => block_hash, error => &format!("{}", e));
                }
            }

            if let Some(block) = self.block_store.get_block(block_hash) {
                // ── CONFIDENTIAL (RingCT) CONSENSUS GATE ───────────────────
                // CRITICAL: block_validator only runs the STRUCTURAL
                // RingValidator check, and apply_block_dag_ordered records
                // confidential key-images/outputs WITHOUT validating. So the
                // full gate (CLSAG crypto + homomorphic balance + on-chain
                // ring-member authenticity + range proofs + cross-block
                // key-image uniqueness) MUST run here, against the state with
                // all earlier new-chain blocks already applied, or a peer block
                // could mint/double-spend confidential value. A block-wide
                // seen-key-image set also catches duplicates within the block.
                {
                    if let Err(msg) =
                        verify_block_confidential_txs(&block, &self.utxo_set, &self.network)
                    {
                        slog_error!("node", "confidential_block_rejected",
                            block => block_hash, reason => &msg);
                        // Fail-atomic unwind: undo this reorg and restore the
                        // previous chain, halting if any step fails.
                        self.unwind_reorg_or_halt(
                            &applied_new,
                            &rolled_back_old,
                            "confidential_block_rejected",
                        );
                        // M3: drop the offending block ONLY if it is a childless
                        // leaf; a mid-reorg-chain non-leaf is left fully intact (see
                        // drop_offending_block_if_leaf). The safety guarantee (never
                        // APPLYING it) holds regardless.
                        self.drop_offending_block_if_leaf(block_hash);
                        return Err(NodeError::BlockRejected(msg));
                    }
                }

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
                            self.unwind_reorg_or_halt(
                                &applied_new,
                                &rolled_back_old,
                                "contract_persist_with_undo_failed",
                            );
                            // M3: drop the offending block ONLY if it is a childless
                            // leaf; a mid-reorg-chain non-leaf is left fully intact
                            // (see drop_offending_block_if_leaf). Pre-M3 this path
                            // deleted nothing, so keeping a non-leaf matches it while
                            // now cleanly removing a childless-leaf offender.
                            self.drop_offending_block_if_leaf(block_hash);
                            return Err(NodeError::Consensus(ConsensusError::BlockValidation(
                                format!(
                                    "contract state persistence failed for block {}: {}",
                                    block_hash, e
                                ),
                            )));
                        }

                        // Store receipts in receipt store (in-memory)
                        for r in &receipts {
                            self.receipt_store.track(r.clone());
                        }

                        // Persist receipts to DB
                        // NOTE: persist_receipts_batch returns () and logs errors
                        // internally. Receipt persistence failure is non-fatal for
                        // consensus (UTXO state is authoritative), but RPC clients
                        // will see missing receipts until recovery replays them.
                        // TODO: refactor persist_receipts_batch to return Result<()>
                        // so callers can handle failures explicitly.
                        use crate::domain::transaction::tx_receipt::persist_receipts_batch;
                        persist_receipts_batch(
                            self.contract_storage.shared_db().as_ref(),
                            &receipts,
                        );

                        // NOTE: receipt_root and state_root are NOT included in the
                        // PoW hash (shadowhash). This is by design: they are computed
                        // AFTER block execution, which happens AFTER PoW validation.
                        // Ethereum has the same architecture — state_root is in the
                        // header but verified post-execution, not pre-mined. The
                        // roots are committed to storage here and verified by peers
                        // during sync via the InvariantChecker below.

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
                            use crate::runtime::vm::testing::invariant_checker::InvariantChecker;
                            use crate::runtime::vm::testing::observability::VM_METRICS;

                            VM_METRICS.record_block();

                            let has_contract_txs = block.body.transactions.iter().any(|tx| {
                                matches!(tx.tx_type, TxType::ContractCreate | TxType::ContractCall)
                            });
                            if has_contract_txs {
                                VM_METRICS.record_call();
                            }

                            // Quick invariant check: verify receipt_root and state_root
                            if let (Some(ref rr), Some(ref sr)) = (&receipt_root, &state_root) {
                                if !InvariantChecker::quick_check(
                                    Some(rr),
                                    Some(sr),
                                    &receipts,
                                    &env,
                                ) {
                                    slog_error!("node", "INVARIANT_VIOLATION",
                                        block => block_hash, height => &block.header.height.to_string());
                                    VM_METRICS.record_violation();
                                    // Invariant violation is a consensus-critical error.
                                    // Roll back this block and reject it.
                                    self.unwind_reorg_or_halt(
                                        &applied_new,
                                        &rolled_back_old,
                                        "INVARIANT_VIOLATION",
                                    );
                                    return Err(NodeError::Consensus(ConsensusError::BlockValidation(
                                        format!("INVARIANT_VIOLATION: receipt/state root mismatch in {}", block_hash)
                                    )));
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
                        let expected_total =
                            expected_reward.checked_add(applied_fees).ok_or_else(|| {
                                self.unwind_reorg_or_halt(
                                    &applied_new,
                                    &rolled_back_old,
                                    "reward_plus_fees_overflow",
                                );
                                NodeError::Consensus(ConsensusError::BlockValidation(
                                    "reward + fees overflow".into(),
                                ))
                            })?;

                        if let Some(cb) = block.body.transactions.first() {
                            if cb.is_coinbase() {
                                let actual_total: u64 = match cb
                                    .outputs
                                    .iter()
                                    .try_fold(0u64, |acc, o| acc.checked_add(o.amount))
                                {
                                    Some(t) => t,
                                    None => {
                                        slog_error!("node", "coinbase_output_overflow", block => block_hash);
                                        self.unwind_reorg_or_halt(
                                            &applied_new,
                                            &rolled_back_old,
                                            "coinbase_output_overflow",
                                        );
                                        return Err(NodeError::BlockRejected(format!(
                                            "coinbase output overflow in {}",
                                            block_hash
                                        )));
                                    }
                                };
                                if actual_total != expected_total {
                                    slog_error!("node", "coinbase_mismatch", block => block_hash, actual => &actual_total.to_string(), expected => &expected_total.to_string());
                                    self.unwind_reorg_or_halt(
                                        &applied_new,
                                        &rolled_back_old,
                                        "coinbase_mismatch",
                                    );
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
                        self.unwind_reorg_or_halt(
                            &applied_new,
                            &rolled_back_old,
                            "utxo_apply_failed",
                        );
                        return Err(NodeError::BlockRejected(format!(
                            "apply_block_dag_ordered failed for {}: {}",
                            block_hash, e
                        )));
                    }
                }
            } else {
                // Missing block in store — unwind this reorg fail-atomically.
                self.unwind_reorg_or_halt(
                    &applied_new,
                    &rolled_back_old,
                    "block_missing_during_virtual_chain_apply",
                );
                return Err(NodeError::BlockRejected(format!(
                    "block {} missing from store during virtual chain apply",
                    block_hash
                )));
            }
        }

        // Update best hash
        if !self.block_store.update_best_hash(&best_tip) {
            // Rollback everything we just applied — the tip cannot be
            // authoritative without a persisted best_hash pointer.
            self.unwind_reorg_or_halt(
                &applied_new,
                &rolled_back_old,
                "best_hash_persist_failed",
            );
            return Err(NodeError::Consensus(ConsensusError::BlockValidation(
                format!("failed to persist best_hash for tip {}", best_tip),
            )));
        }

        // Publish next difficulty + deferred state commitment + tips for
        // getblocktemplate. CONSENSUS-CRITICAL (external audit C4 equivalence) — see
        // publish_mining_template for the full rationale and the anchor invariant.
        self.publish_mining_template(&best_tip);

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
                                cursor = b.header.resolved_selected_parent().unwrap_or_default();
                            } else {
                                break;
                            }
                        }
                    }
                    if !to_prune.is_empty() {
                        let pruned = self.utxo_set.prune_finalized_undo_data(&to_prune);
                        let contract_pruned =
                            self.contract_storage.prune_finalized_undo_data(&to_prune);
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
    fn rollback_contract_block(&self, block_hash: &str) -> Result<(), NodeError> {
        // Distinguish "no undo data" from "corrupt/read-failed undo data".
        // Corruption here is consensus-critical and must not be silently skipped.
        let has_undo = self
            .contract_storage
            .has_undo_data_strict(block_hash)
            .map_err(|e| {
                NodeError::Consensus(ConsensusError::BlockValidation(format!(
                    "contract undo probe failed for {}: {}",
                    block_hash, e
                )))
            })?;
        if has_undo {
            self.contract_storage.rollback_block(block_hash).map_err(|e| {
                NodeError::Consensus(ConsensusError::BlockValidation(format!(
                    "contract rollback failed for {}: {}",
                    block_hash, e
                )))
            })?;
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
                delete_receipts_for_block(self.contract_storage.shared_db().as_ref(), &tx_hashes);
                self.receipt_store.remove_tx_hashes(&tx_hashes);
            }
        }
        Ok(())
    }

    /// Roll back a block's contract state, logging on failure. Returns `false`
    /// if the rollback FAILED. Consensus-recovery callers MUST treat `false` as
    /// a failed restore (see `unwind_reorg_or_halt`) — silently discarding it is
    /// what let a failed rollback leave indeterminate state (external audit M4).
    fn rollback_contract_block_best_effort(&self, block_hash: &str) -> bool {
        if let Err(e) = self.rollback_contract_block(block_hash) {
            slog_error!("node", "CRITICAL_contract_rollback_failed",
                block => block_hash, error => &format!("{}", e));
            return false;
        }
        true
    }

    /// FAIL-ATOMIC reorg unwind — the ONE recovery path for every reorg-failure
    /// site in `recompute_virtual_chain` (external audit M4).
    ///
    /// Undoes every block this reorg applied, then restores the chain that was
    /// rolled back to make room for it. If ANY step fails — a UTXO rollback, a
    /// contract rollback, a MISSING old block body, an old-chain re-apply, or a
    /// contract re-persist — then committed state represents NEITHER the old nor
    /// the new chain. That is unrecoverable in-process, and continuing would
    /// serve and relay corrupt consensus state, so we HALT. A restart runs the
    /// verified rebuild/replay from the durable BlockStore.
    ///
    /// Do NOT hand-roll a best-effort variant of this: seven such copies existed,
    /// each discarding results and returning `Err` without halting, which is
    /// exactly the silent-corruption path this function exists to remove.
    fn unwind_reorg_or_halt(&self, applied_new: &[String], rolled_back_old: &[String], reason: &str) {
        let mut restore_failed = false;

        // 1) Undo everything this reorg applied, newest first.
        for hash in applied_new.iter().rev() {
            if self.utxo_set.rollback_block_undo(hash).is_err() {
                slog_error!("node", "reorg_unwind_utxo_rollback_failed", block => hash);
                restore_failed = true;
            }
            if !self.rollback_contract_block_best_effort(hash) {
                restore_failed = true;
            }
        }

        // 2) Restore the previously-applied chain, oldest-first order preserved.
        for hash in rolled_back_old.iter().rev() {
            match self.block_store.get_block(hash) {
                Some(old_block) => {
                    if self
                        .utxo_set
                        .apply_block_dag_ordered(
                            &old_block.body.transactions,
                            old_block.header.height,
                            hash,
                        )
                        .is_err()
                    {
                        slog_error!("node", "reorg_unwind_old_chain_reapply_failed", block => hash);
                        restore_failed = true;
                    }
                    let (_, _, _, env) =
                        self.execute_contract_transactions(&old_block, &self.contract_storage);
                    if let Err(pe) =
                        env.persist_with_undo(&self.contract_storage, hash, None, None)
                    {
                        slog_error!("node", "CRITICAL_contract_restore_failed",
                            block => hash, error => &format!("{}", pe));
                        restore_failed = true;
                    }
                }
                None => {
                    // These blocks were applied moments ago and sit far inside the
                    // reorg window, so a missing body means real store corruption,
                    // not pruning. The old chain cannot be reconstructed.
                    slog_error!("node", "reorg_unwind_old_block_missing", block => hash);
                    restore_failed = true;
                }
            }
        }

        if restore_failed {
            slog_error!("node", "FATAL_reorg_restore_failed_halting", reason => reason);
            std::process::exit(1);
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
    ) -> (
        Vec<TxReceipt>,
        Option<String>,
        Option<String>,
        ExecutionEnvironment,
    ) {
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
                    let deployer = tx
                        .inputs
                        .first()
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
                                "ContractCall tx '{}' has no contract_address",
                                tx.hash
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
                    let caller = tx
                        .inputs
                        .first()
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
                let is_contract_tx =
                    matches!(tx.tx_type, TxType::ContractCreate | TxType::ContractCall);
                if is_contract_tx {
                    has_contract_txs = true;
                    receipts.push(TxReceipt::from_execution(
                        &tx.hash,
                        &ExecutionResult::Error {
                            gas_used: 0,
                            message: msg.clone(),
                        },
                        &block.header.hash,
                        block.header.height,
                        tx_index as u32,
                    ));
                } else {
                    receipts.push(TxReceipt::from_execution(
                        &tx.hash,
                        &ExecutionResult::Success {
                            gas_used: 0,
                            return_data: vec![],
                            logs: vec![],
                        },
                        &block.header.hash,
                        block.header.height,
                        tx_index as u32,
                    ));
                }
            }
            let (receipt_root, state_root) = if has_contract_txs {
                (
                    Some(compute_receipt_root(&receipts)),
                    Some(env.state.state_root()),
                )
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
                                        &ExecutionResult::Error {
                                            gas_used: 0,
                                            message: "invalid deploy payload".into(),
                                        },
                                        &block.header.hash,
                                        block.header.height,
                                        tx_index as u32,
                                    ));
                                    continue;
                                }
                            },
                            None => {
                                receipts.push(TxReceipt::from_execution(
                                    &tx.hash,
                                    &ExecutionResult::Error {
                                        gas_used: 0,
                                        message: "missing deploy payload".into(),
                                    },
                                    &block.header.hash,
                                    block.header.height,
                                    tx_index as u32,
                                ));
                                continue;
                            }
                        }
                    };

                    let deployer = tx
                        .inputs
                        .first()
                        .map(|i| i.owner.clone())
                        .unwrap_or_default();
                    if deployer.is_empty() {
                        receipts.push(TxReceipt::from_execution(
                            &tx.hash,
                            &ExecutionResult::Error {
                                gas_used: 0,
                                message: "ContractCreate missing deployer (no inputs)".into(),
                            },
                            &block.header.hash,
                            block.header.height,
                            tx_index as u32,
                        ));
                        continue;
                    }
                    let value = tx.outputs.first().map(|o| o.amount).unwrap_or(0);
                    // effective_gas_limit: the exact amount the block-gas
                    // validator charged for this tx (single source of truth).
                    let gas_limit = tx.effective_gas_limit();

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
                            &block.header.hash,
                            block.header.height,
                            tx_index as u32,
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
                    // Route the top-level entry through the reentrancy guard so the
                    // entry contract is registered (closes the A->B->A entry-point
                    // reentrancy gap; child frames already use the guarded path).
                    let outcome = env.execute_frame_guarded(&call_ctx);
                    let exec_result = match outcome {
                        CallOutcome::Success {
                            gas_used,
                            return_data,
                            logs,
                        } => {
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
                            if let Err(e) = env.state.commit(deploy_snapshot) {
                                slog_error!("node", "contract_deploy_commit_failed",
                                    tx => &tx.hash, error => &format!("{}", e));
                                // Commit failure means the deploy state is corrupt.
                                // Roll back instead and report as error.
                                env.state.rollback(deploy_snapshot).ok();
                                receipts.push(TxReceipt::from_execution(
                                    &tx.hash,
                                    &ExecutionResult::Error {
                                        gas_used,
                                        message: format!("deploy commit failed: {}", e),
                                    },
                                    &block.header.hash,
                                    block.header.height,
                                    tx_index as u32,
                                ));
                                continue;
                            }
                            if let Err(e) = env.state.increment_nonce(&deployer) {
                                slog_error!("node", "deployer_nonce_increment_failed",
                                    tx => &tx.hash, deployer => &deployer, error => &format!("{}", e));
                            }
                            ExecutionResult::Success {
                                gas_used,
                                return_data,
                                logs,
                            }
                        }
                        CallOutcome::Revert {
                            gas_used,
                            return_data,
                        } => {
                            // Revert path: roll back the init
                            // code + constructor effects, not just
                            // the call's own snapshot. The
                            // inner `execute_frame` already rolled
                            // back its own nested snapshot, but the
                            // `set_code(init)` we did above was
                            // OUTSIDE that nested snapshot, so we
                            // still need to rewind our own one.
                            env.state.rollback(deploy_snapshot).ok();
                            ExecutionResult::Revert {
                                gas_used,
                                reason: Self::decode_revert_reason(&return_data),
                            }
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
                        &tx.hash,
                        &exec_result,
                        &block.header.hash,
                        block.header.height,
                        tx_index as u32,
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
                                &block.header.hash,
                                block.header.height,
                                tx_index as u32,
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
                                        &ExecutionResult::Error {
                                            gas_used: 0,
                                            message: "invalid calldata".into(),
                                        },
                                        &block.header.hash,
                                        block.header.height,
                                        tx_index as u32,
                                    ));
                                    continue;
                                }
                            },
                            None => {
                                receipts.push(TxReceipt::from_execution(
                                    &tx.hash,
                                    &ExecutionResult::Error {
                                        gas_used: 0,
                                        message: "missing calldata".into(),
                                    },
                                    &block.header.hash,
                                    block.header.height,
                                    tx_index as u32,
                                ));
                                continue;
                            }
                        }
                    };
                    let caller = tx
                        .inputs
                        .first()
                        .map(|i| i.owner.clone())
                        .unwrap_or_default();
                    if caller.is_empty() {
                        receipts.push(TxReceipt::from_execution(
                            &tx.hash,
                            &ExecutionResult::Error {
                                gas_used: 0,
                                message: "ContractCall missing caller (no inputs)".into(),
                            },
                            &block.header.hash,
                            block.header.height,
                            tx_index as u32,
                        ));
                        continue;
                    }
                    let value = tx.outputs.first().map(|o| o.amount).unwrap_or(0);
                    // effective_gas_limit: the exact amount the block-gas
                    // validator charged for this tx (single source of truth).
                    let gas_limit = tx.effective_gas_limit();

                    // Lazy-load the target's code from disk on
                    // first touch. `load_contract_from_storage`
                    // only populates the account row; the code
                    // blob lives under `code:{addr}` and is read
                    // here. Previously this was a no-error `.ok()`
                    // — so a set_code failure (disk full,
                    // permissions, corruption) silently dropped
                    // the contract's runtime code and the CALL
                    // executed as if it were an empty address.
                    if let Some(code_hex) = contract_storage.get_state(&format!("code:{}", target))
                    {
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
                                            &block.header.hash,
                                            block.header.height,
                                            tx_index as u32,
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
                                    &block.header.hash,
                                    block.header.height,
                                    tx_index as u32,
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

                    // Route the top-level entry through the reentrancy guard so the
                    // entry contract is registered (closes the A->B->A entry-point
                    // reentrancy gap; child frames already use the guarded path).
                    let outcome = env.execute_frame_guarded(&call_ctx);
                    let exec_result = match outcome {
                        CallOutcome::Success {
                            gas_used,
                            return_data,
                            logs,
                        } => ExecutionResult::Success {
                            gas_used,
                            return_data,
                            logs,
                        },
                        CallOutcome::Revert {
                            gas_used,
                            return_data,
                        } => ExecutionResult::Revert {
                            gas_used,
                            reason: Self::decode_revert_reason(&return_data),
                        },
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
                        &tx.hash,
                        &exec_result,
                        &block.header.hash,
                        block.header.height,
                        tx_index as u32,
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
                        &ExecutionResult::Success {
                            gas_used: 0,
                            return_data: vec![],
                            logs: vec![],
                        },
                        &block.header.hash,
                        block.header.height,
                        tx_index as u32,
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

    /// Highest chain-height among current tips (cheap; used by the P0-C orphan
    /// pre-cache bound). 0 if there are no tips.
    fn best_tip_height(&self) -> u64 {
        self.ghostdag
            .get_tips()
            .iter()
            .map(|t| self.ghostdag.get_chain_height(t))
            .max()
            .unwrap_or(0)
    }

    /// P0-C: true if `height`'s UmbraHash epoch is more than
    /// MAX_ORPHAN_FUTURE_EPOCHS beyond our best tip's epoch — accepting it as an
    /// orphan would force epoch_seed/mkcache work for an absurd, attacker-chosen
    /// height. Cheap (no hashing).
    fn orphan_epoch_too_far(&self, height: u64) -> bool {
        orphan_epoch_out_of_bound(height, self.best_tip_height())
    }

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
        let counts = match self.orphan_count_by_peer.lock() {
            Ok(c) => c,
            Err(_) => {
                slog_error!("node", "orphan_count_lock_poisoned");
                return; // Fail-closed: reject orphan on lock failure
            }
        };
        let peer_count = counts.get(peer_id).copied().unwrap_or(0);
        if peer_count >= MAX_ORPHAN_PER_PEER {
            slog_warn!("node", "orphan_per_peer_limit", peer => peer_id, limit => &MAX_ORPHAN_PER_PEER.to_string());
            return;
        }
        drop(counts); // Release lock before acquiring orphan_pool lock

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
                by_parent
                    .entry(parent_hash.clone())
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
        // Trusted seeds are never rate-limited (they must serve unbounded IBD
        // backfill to a lagging peer). This is the FullNode-local limiter,
        // separate from DosGuard, so it needs its own whitelist check.
        if crate::service::network::dos_guard::is_whitelisted(peer_id) {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Ok(mut timestamps) = self.peer_block_timestamps.lock() {
            // Bound the map: when it grows large, drop peers whose timestamps are ALL
            // stale (they stopped submitting) — otherwise rotated peer_ids leak entries
            // forever, since a peer's entry is only revisited when it submits again (B4-L01).
            if timestamps.len() > MAX_TRACKED_PEERS {
                timestamps.retain(|_, ts| ts.iter().any(|t| now.saturating_sub(*t) < 60));
            }
            let entry = timestamps
                .entry(peer_id.to_string())
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
                Ok(mut by_parent) => by_parent.remove(&current_parent).unwrap_or_default(),
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
                                if *c == 0 {
                                    counts.remove(&peer_id);
                                }
                            }
                        }
                        // Clean this orphan's dangling entries under its OTHER parents:
                        // add_orphan registered it under EVERY parent, and it was only
                        // drained from the parent that arrived, leaking hashes under the
                        // rest (evict_expired can't reclaim them once pooled) — B4-L02.
                        if let Ok(mut by_parent) = self.orphan_by_parent.lock() {
                            for p in &block.header.parents {
                                let now_empty = if let Some(list) = by_parent.get_mut(p) {
                                    list.retain(|h| h != &hash);
                                    list.is_empty()
                                } else {
                                    false
                                };
                                if now_empty {
                                    by_parent.remove(p);
                                }
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
                                let list = by_parent.entry(p.clone()).or_insert_with(Vec::new);
                                if !list.contains(&hash) {
                                    list.push(hash.clone());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // Permanent failure — decrement peer count, log warning
                        if let Ok(mut counts) = self.orphan_count_by_peer.lock() {
                            if let Some(c) = counts.get_mut(&peer_id) {
                                *c = c.saturating_sub(1);
                                if *c == 0 {
                                    counts.remove(&peer_id);
                                }
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

        let expired: Vec<String> = pool
            .iter()
            .filter(|(_, (_, ts, _))| now.saturating_sub(*ts) > ORPHAN_EXPIRY_SECS)
            .map(|(hash, _)| hash.clone())
            .collect();

        if expired.is_empty() {
            return;
        }

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
                        if *c == 0 {
                            counts.remove(peer_id);
                        }
                    }
                }
            }
        }

        for hash in expired {
            pool.remove(&hash);
        }
    }

    /// Process genesis block — same pipeline minus parent validation.
    /// Publish the NEXT block's mining-template inputs — next difficulty, the M5
    /// deferred state commitment, and the DAG tips — into BOTH the per-instance
    /// `mining_state` cell AND the process-default cell (the daemon serves
    /// getblocktemplate with `RpcState::mining_state = None`, so it reads the
    /// process-default). MUST be called after EVERY tip change so a template
    /// consumer mines a block the validator accepts.
    ///
    /// CONSENSUS-CRITICAL (external audit C4 equivalence): difficulty and the
    /// commitment are anchored on `select_parent` of the SAME canonical tip set
    /// the template will use — NOT the single `best_tip` (chosen by
    /// select_best_tip, a DIFFERENT function: cumulative_work-first with the
    /// opposite hash tie-break). Anchoring on best_tip made a reconvergence block
    /// merging sibling tips get stamped f(best_tip) but validated against
    /// f(select_parent(parents)) and universally rejected → production halt. Tips
    /// are canonicalised exactly as the RPC handler does (non-empty, sorted,
    /// deduped, capped at MAX_PARENTS); backfilled min-parent ancestors the RPC
    /// may add are older (lower blue score) and never change select_parent.
    ///
    /// Called from BOTH the normal accept path (recompute_virtual_chain) AND
    /// fresh-chain genesis acceptance (process_genesis). The two paths MUST
    /// publish identically: on a fresh chain the daemon accepts genesis without
    /// recompute_virtual_chain, so without a publish here the process-default
    /// would still hold the empty-parent genesis commitment seeded in
    /// FullNode::new (store empty at construction), and every height-1 block
    /// would be rejected (commitment mismatch) → chain frozen at genesis.
    fn publish_mining_template(&self, best_tip: &str) {
        let mut tips = self.dag_manager.get_tips();
        tips.retain(|h| !h.is_empty());
        tips.sort();
        tips.dedup();
        tips.truncate(crate::config::consensus::consensus_params::ConsensusParams::MAX_PARENTS);
        if tips.is_empty() {
            return;
        }
        // Keep the running retarget engine rebuilt from the canonical best tip. It
        // is NON-authoritative now (validation recomputes per block); some RPC/stats
        // read its EMA, so keep it fresh.
        if self.block_store.get_block(best_tip).is_some() {
            if let Ok(mut retarget) = self.retarget.lock() {
                let (fresh, _) = Self::build_retarget_from_canonical(
                    &self.block_store,
                    &self.ghostdag,
                    &self.network,
                    best_tip,
                );
                *retarget = fresh;
            }
        }
        let sp = self.ghostdag.select_parent(&tips);
        let anchor = if sp.is_empty() { best_tip.to_string() } else { sp };
        let diff = self.expected_difficulty_for_selected_parent(&anchor);
        self.mining_state.set_next_difficulty(diff);
        set_next_difficulty(diff);
        // M5: publish the NEXT block's deferred state commitment over the SAME
        // canonical tips as next_difficulty, so the miner stamps exactly what the
        // validator recomputes from the block's parents (parity). Compute ONCE and
        // write BOTH cells, immediately before the tips writes so the
        // commitment↔tips pair is published back-to-back (a stale cross-read just
        // yields a rejected template the miner retries — never an unsound accept).
        let psc = expected_prev_state_commitment(&tips, &self.ghostdag, &self.block_store);
        self.mining_state.set_prev_state_commitment(Some(psc.clone()));
        set_prev_state_commitment(Some(psc));
        self.mining_state.set_dag_tips(tips.clone());
        set_dag_tips(tips);
    }

    /// Republish the mining template over the CURRENT canonical best/tips. Call
    /// this ONCE after startup recovery has settled the DAG/GHOSTDAG state.
    ///
    /// WHY IT'S REQUIRED: FullNode::new seeds the mining cells from the DAG as it
    /// exists AT CONSTRUCTION — which the daemon builds BEFORE
    /// start()->verify_and_recover, so on a restart that rebuilds a corrupt DAG
    /// (rebuild_dag/rebuild_ghostdag) the seed is stale. recompute_virtual_chain
    /// (the restart branch's republish) early-returns WITHOUT publishing whenever
    /// the recomputed best equals the persisted best (the normal case). Under M5
    /// that stale commitment is not merely suboptimal: getblocktemplate would serve
    /// a value the height>=1 validator recomputes differently and rejects — a
    /// block-production halt on that node. Republishing over the post-recovery tips
    /// closes this. Idempotent (safe to call on the fresh-genesis path too).
    pub fn republish_mining_template(&self) {
        let best = self.block_store.get_best_hash().unwrap_or_default();
        if !best.is_empty() {
            self.publish_mining_template(&best);
        }
    }

    pub fn process_genesis(&self, block: &Block) -> Result<(), NodeError> {
        // ═══════════════════════════════════════════════════════════════
        // PHASE 1: VALIDATE (read-only — NO state changes)
        // ═══════════════════════════════════════════════════════════════

        // 1a: Structural validation (PoW, coinbase, etc.)
        let result =
            BlockValidator::validate_block_full_with_network(block, &self.utxo_set, &self.network);
        if !result.valid {
            return Err(NodeError::BlockRejected(format!(
                "Genesis validation failed: {}",
                result.reason.unwrap_or_else(|| "unknown".to_string())
            )));
        }
        // Skip parent validation — genesis has no parents by definition

        // 1b: UTXO validation BEFORE any writes (genesis coinbase only)
        use crate::domain::utxo::utxo_validator::UtxoValidator;
        UtxoValidator::validate_block_utxos(block, &self.utxo_set, 0).map_err(|e| {
            NodeError::BlockRejected(format!("Genesis UTXO validation failed: {}", e))
        })?;

        // ═══════════════════════════════════════════════════════════════
        // PHASE 2: COMMIT (block is fully validated)
        // ═══════════════════════════════════════════════════════════════

        // Save block
        if !self.block_store.save_block(block) {
            return Err(NodeError::BlockRejected(
                "Failed to save genesis to BlockStore".to_string(),
            ));
        }

        // DAG insertion — genesis MUST succeed, otherwise the node starts
        // with an inconsistent state from the very first block.
        if let Err(e) = self.dag_manager.add_block_validated(block, true) {
            let _ = self.block_store.delete_block(&block.header.hash);
            return Err(NodeError::BlockRejected(format!(
                "Genesis DAG insertion failed (fatal): {}",
                e
            )));
        }

        // GHOSTDAG ordering
        let dag_block = DagBlock {
            hash: block.header.hash.clone(),
            parents: block.header.parents.clone(),
            height: block.header.height,
            timestamp: block.header.timestamp,
        };
        if let Err(e) = self.ghostdag.add_block(dag_block) {
            if let Err(re) = self.dag_manager.remove_block_topology(&block.header.hash) {
                slog_error!("node", "dag_topology_rollback_failed",
                    hash => &block.header.hash, error => &re.to_string());
            }
            let _ = self.block_store.delete_block(&block.header.hash);
            slog_error!("node", "ghostdag_add_failed_cleanup",
                hash => &block.header.hash, error => &e.to_string());
            return Err(NodeError::BlockRejected(format!("GHOSTDAG: {}", e)));
        }

        // UTXO write + commitment ATOMICALLY (validation already passed in Phase 1)
        let _commitment = self
            .utxo_set
            .apply_block_write_with_commitment(&block.body.transactions, 0, &block.header.hash)
            .map_err(|e| {
                // Genesis failure rollback: clear GHOSTDAG state and remove the
                // just-inserted genesis topology/block so startup remains clean.
                self.ghostdag.clear_all();
                let _ = self.dag_manager.remove_block_topology(&block.header.hash);
                let _ = self.block_store.delete_block(&block.header.hash);
                slog_error!("node", "genesis_utxo_failed_cleanup",
                error => &format!("{}", e),
                note => "rolled back genesis topology and storage");
                NodeError::BlockRejected(format!("Genesis UTXO write failed: {}", e))
            })?;

        // Genesis is always best
        if !self.block_store.update_best_hash(&block.header.hash) {
            let _ = self.utxo_set.rollback_block_undo(&block.header.hash);
            self.rollback_contract_block_best_effort(&block.header.hash);
            self.ghostdag.clear_all();
            let _ = self.dag_manager.remove_block_topology(&block.header.hash);
            let _ = self.block_store.delete_block(&block.header.hash);
            slog_error!("node", "genesis_best_hash_persist_failed_cleanup",
                hash => &block.header.hash,
                note => "rolled back genesis UTXO/DAG/GHOSTDAG/BlockStore");
            return Err(NodeError::BlockRejected(
                "Failed to persist best_hash for genesis block".to_string(),
            ));
        }

        // M5 (fresh-chain halt fix): genesis is now the sole DAG tip. Publish the
        // mining template over the real tips ([genesis]) so the height-1
        // getblocktemplate serves compute_prev_state_commitment(genesis_hash) — the
        // exact value the validator recomputes for parents=[genesis]. Without this,
        // the process-default cell still holds the empty-parent genesis commitment
        // seeded in FullNode::new (store empty), and every height-1 block is
        // rejected → the chain deadlocks at genesis on every fresh bring-up. The
        // daemon's fresh-chain branch does NOT call recompute_virtual_chain, so this
        // publish must happen here (the same helper the accept path uses).
        self.publish_mining_template(&block.header.hash);

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

/// Run the confidential (RingCT) consensus gate over every confidential tx in a
/// block, against `utxo_set` (which MUST already reflect all earlier blocks in
/// the chain being applied). Returns `Err(reason)` on the first failure. A
/// block-wide seen-key-image set also catches duplicate key images within the
/// same block. This is the gate that `apply_block_dag_ordered` relies on having
/// run (it records confidential state without validating).
fn verify_block_confidential_txs(
    block: &Block,
    utxo_set: &UtxoSet,
    network: &NetworkMode,
) -> Result<(), String> {
    use std::collections::HashSet;
    let mut seen_ki: HashSet<String> = HashSet::new();
    for tx in &block.body.transactions {
        if tx.is_confidential() {
            crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx(
                tx, utxo_set, network, &mut seen_ki,
            )
            .map_err(|e| format!("confidential tx {} failed consensus gate: {}", tx.hash, e))?;
        } else if tx.is_shield() {
            // Shield (transparent -> confidential): same shield gate as mempool +
            // block-UTXO validation, so the reorg/apply path never records
            // confidential shield state without the crypto/balance check.
            crate::engine::privacy::ringct::confidential_consensus::verify_shield_tx(
                tx, utxo_set, network,
            )
            .map_err(|e| format!("shield tx {} failed consensus gate: {}", tx.hash, e))?;
        }
    }
    Ok(())
}

/// Pure P0-C bound: true if `height`'s UmbraHash epoch is more than
/// MAX_ORPHAN_FUTURE_EPOCHS beyond `best_height`'s epoch. Extracted from
/// `FullNode::orphan_epoch_too_far` so the rule is testable without a live node.
fn orphan_epoch_out_of_bound(height: u64, best_height: u64) -> bool {
    use crate::engine::mining::algorithms::umbrahash::epoch_of;
    epoch_of(height) > epoch_of(best_height).saturating_add(MAX_ORPHAN_FUTURE_EPOCHS)
}

#[cfg(test)]
mod tests {
    use super::{orphan_epoch_out_of_bound, verify_block_confidential_txs, FullNode};

    #[test]
    fn orphan_epoch_bound_rejects_absurd_height_but_allows_near_tip() {
        // P0-C: the cheap tip-relative epoch bound must reject an absurd-height
        // orphan (which would force epoch_seed/mkcache work) while allowing any
        // legitimately near-tip block, and it must SCALE with the real tip.
        use crate::engine::mining::algorithms::umbrahash::{epoch_of, EPOCH_BLOCKS, UMBRA_MAX_HEIGHT};
        use super::MAX_ORPHAN_FUTURE_EPOCHS as MARGIN;

        let tip = 1_500_000u64; // epoch 0 (below EPOCH_BLOCKS = 3M)
        assert!(!orphan_epoch_out_of_bound(tip, tip), "same-epoch orphan allowed");
        assert!(!orphan_epoch_out_of_bound(tip + 1, tip), "tip+1 allowed");
        // Exactly MARGIN epochs ahead is allowed; one epoch past it is rejected.
        let allowed = (epoch_of(tip) + MARGIN) * EPOCH_BLOCKS;
        assert!(!orphan_epoch_out_of_bound(allowed, tip), "within-margin epoch allowed");
        let rejected = (epoch_of(tip) + MARGIN + 1) * EPOCH_BLOCKS;
        assert!(orphan_epoch_out_of_bound(rejected, tip), "past-margin epoch rejected");
        // The near-ceiling flood height (epoch ~333k) is rejected outright.
        assert!(
            orphan_epoch_out_of_bound(UMBRA_MAX_HEIGHT - 1, tip),
            "absurd 1e12-height flood rejected"
        );
        // Bound scales with the tip: a mature chain accepts correspondingly higher
        // orphans but still rejects the absurd flood.
        let mature = 100 * EPOCH_BLOCKS; // epoch 100
        assert!(!orphan_epoch_out_of_bound(mature + 1, mature), "mature near-tip allowed");
        assert!(
            orphan_epoch_out_of_bound(UMBRA_MAX_HEIGHT - 1, mature),
            "1e12 still rejected at epoch 100"
        );
    }

    #[test]
    fn block_rate_limit_exceeds_network_production_rate() {
        // A peer merely relaying the chain sends ~BPS*60 blocks/min; a peer
        // serving an IBD backfill sends far more. The per-peer block rate limit
        // MUST sit above the network's own production rate (with headroom) or
        // every relaying peer is wrongly banned and lagging nodes can never
        // converge. Regression guard for the old hardcoded 60/min, which was
        // BELOW the 10-BPS network rate of 600/min.
        use super::MAX_BLOCKS_PER_PEER_PER_MIN;
        let net_rate_per_min =
            crate::config::consensus::consensus_params::ConsensusParams::BLOCKS_PER_SECOND
                as usize
                * 60;
        assert!(
            MAX_BLOCKS_PER_PEER_PER_MIN >= net_rate_per_min * 2,
            "per-peer block limit {} must exceed 2x the network rate {}/min so relaying peers are not banned",
            MAX_BLOCKS_PER_PEER_PER_MIN,
            net_rate_per_min
        );
    }

    #[test]
    fn retarget_rebuild_deterministic_from_canonical_chain() {
        // The retarget engine must be a pure function of the canonical
        // selected-parent chain (so all nodes agree on the next difficulty and
        // a reorg cannot leave a divergent target). Same chain → same result.
        use crate::config::node::node_config::NetworkMode;
        use crate::domain::block::block::Block;
        use crate::domain::block::block_body::BlockBody;
        use crate::domain::block::block_header::BlockHeader;
        use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;
        use crate::infrastructure::storage::rocksdb::core::db::NodeDB;
        use std::sync::atomic::{AtomicU64, Ordering};

        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        // Unique per RUN (not just per process) so a leftover temp dir from a
        // prior run can't make save_block reject "g" as a duplicate.
        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = format!(
            "{}/rt_canon_{}_{}_{}",
            std::env::temp_dir().display(),
            std::process::id(),
            uniq,
            id
        );
        let store = BlockStore::new(NodeDB::new(&path).unwrap().shared()).unwrap();

        let mk = |hash: &str, height: u64, parent: Option<&str>, ts: u64| Block {
            header: BlockHeader {
                version: 1,
                hash: hash.into(),
                parents: parent.map(|p| vec![p.to_string()]).unwrap_or_default(),
                merkle_root: "m".into(),
                timestamp: ts,
                nonce: 0,
                difficulty: 1000,
                height,
                blue_score: height,
                selected_parent: parent.map(|p| p.to_string()),
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
                mix_hash: String::new(),
                prev_state_commitment: None,
            },
            body: BlockBody { transactions: vec![] },
        };
        assert!(store.save_block(&mk("g", 0, None, 1000)));
        assert!(store.save_block(&mk("b1", 1, Some("g"), 1010)));
        assert!(store.save_block(&mk("b2", 2, Some("b1"), 1020)));

        let net = NetworkMode::Regtest;
        let gd = crate::engine::dag::ghostdag::ghostdag::GhostDag::new(&format!("{}_gd", path))
            .unwrap();
        let (_e1, d1) = FullNode::build_retarget_from_canonical(&store, &gd, &net, "b2");
        let (_e2, d2) = FullNode::build_retarget_from_canonical(&store, &gd, &net, "b2");
        assert_eq!(d1, d2, "rebuild must be deterministic for the same canonical chain");
        assert!(d1 > 0, "difficulty must be positive");
    }

    #[test]
    fn retarget_is_independent_of_dag_width_the_node_happens_to_hold() {
        // CONSENSUS-CRITICAL REGRESSION GUARD. Two nodes with the IDENTICAL
        // selected chain but a DIFFERENT set of same-height side/red blocks MUST
        // compute the SAME next difficulty. Before the fix, difficulty depended
        // on `blocks_at_height` (the LOCAL DAG width a node happens to hold), so
        // a full miner (holds all siblings) and a syncing follower (holds only
        // the selected chain) diverged wildly — this exact test produced 242 vs
        // 11 — and the follower rejected the miner's next block forever with
        // "difficulty mismatch", stalling IBD past the tip. The fix keys the
        // DAG-rate weight on the block's own PoW-committed `parents.len()`, which
        // is identical on every node. This test asserts the two agree.
        use crate::config::node::node_config::NetworkMode;
        use crate::domain::block::block::Block;
        use crate::domain::block::block_body::BlockBody;
        use crate::domain::block::block_header::BlockHeader;
        use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;
        use crate::infrastructure::storage::rocksdb::core::db::NodeDB;
        use std::sync::atomic::{AtomicU64, Ordering};

        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // A block with an explicit parent list; `selected_parent` is the first
        // entry, so the canonical walk still follows the linear selected chain.
        let mk = |hash: &str, height: u64, parents: &[&str], ts: u64| Block {
            header: BlockHeader {
                version: 1,
                hash: hash.into(),
                parents: parents.iter().map(|p| p.to_string()).collect(),
                merkle_root: "m".into(),
                timestamp: ts,
                nonce: 0,
                difficulty: 1000,
                height,
                blue_score: height,
                selected_parent: parents.first().map(|p| p.to_string()),
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
                mix_hash: String::new(),
                prev_state_commitment: None,
            },
            body: BlockBody { transactions: vec![] },
        };
        const N: u64 = 80;
        // OFF-TARGET spacing (3s ≫ 1s target) so the retarget's DAG-rate
        // correction (retarget.rs:199) is NOT floored to a no-op: with slower
        // blocks blended_time is large, so dividing it by the DAG-to-chain
        // ratio actually changes the computed difficulty. This is the regime the
        // live chain runs in — an on-target chain would hide the bug.
        const DT: u64 = 3;
        // Extra red siblings per height on the "full" node only. Under the OLD
        // (buggy) code these inflated its blocks_at_height and diverged it from
        // the follower; under the fix they are irrelevant (never walked).
        const SIBS: u64 = 2;
        let build = |label: &str, with_siblings: bool| -> u64 {
            let path = format!(
                "{}/rt_width_{}_{}_{}_{}",
                std::env::temp_dir().display(),
                label,
                std::process::id(),
                uniq,
                id
            );
            let store = BlockStore::new(NodeDB::new(&path).unwrap().shared()).unwrap();
            assert!(store.save_block(&mk("h0", 0, &[], 1000)));
            assert!(store.save_block(&mk("h1", 1, &["h0"], 1000 + DT)));
            let mut prev = "h1".to_string();
            let mut prev_prev = "h0".to_string();
            for h in 2..=N {
                let hash = format!("h{}", h);
                // Each selected block MERGES its grandparent (both on the selected
                // chain, present in BOTH stores) → parents.len()=2, so the DAG-rate
                // path is ACTIVE and, being header-committed, deterministic.
                assert!(store.save_block(&mk(
                    &hash,
                    h,
                    &[prev.as_str(), prev_prev.as_str()],
                    1000 + h * DT
                )));
                if with_siblings {
                    for s in 0..SIBS {
                        // Red siblings at this height (full node only). Same-height
                        // as the selected block, so ONLY blocks_at_height sees them.
                        let sib = format!("r{}_{}", h, s);
                        assert!(store.save_block(&mk(&sib, h, &[prev.as_str()], 1000 + h * DT)));
                    }
                }
                prev_prev = prev;
                prev = hash;
            }
            let tip = format!("h{}", N);
            let gd = crate::engine::dag::ghostdag::ghostdag::GhostDag::new(&format!("{}_gd", path))
                .unwrap();
            let (_e, d) =
                FullNode::build_retarget_from_canonical(&store, &gd, &NetworkMode::Regtest, &tip);
            d
        };
        let full_node_diff = build("full", true);
        let syncing_diff = build("partial", false);
        assert_eq!(
            full_node_diff, syncing_diff,
            "next difficulty must be a pure function of the SELECTED chain, not the \
             set of same-height siblings a node happens to have downloaded — a \
             syncing node otherwise rejects the miner's next block forever"
        );
    }

    #[test]
    fn cumulative_work_sums_difficulty_and_prefers_heavier_equal_height_tip() {
        use crate::domain::block::block::Block;
        use crate::domain::block::block_body::BlockBody;
        use crate::domain::block::block_header::BlockHeader;
        use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;
        use crate::infrastructure::storage::rocksdb::core::db::NodeDB;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicU64, Ordering};

        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = format!(
            "{}/cwork_{}_{}_{}",
            std::env::temp_dir().display(),
            std::process::id(),
            uniq,
            id
        );
        let store = BlockStore::new(NodeDB::new(&path).unwrap().shared()).unwrap();

        let mk = |hash: &str, height: u64, parent: Option<&str>, diff: u64| Block {
            header: BlockHeader {
                version: 1,
                hash: hash.into(),
                parents: parent.map(|p| vec![p.to_string()]).unwrap_or_default(),
                merkle_root: "m".into(),
                timestamp: 1000 + height,
                nonce: 0,
                difficulty: diff,
                height,
                blue_score: height,
                selected_parent: parent.map(|p| p.to_string()),
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
                mix_hash: String::new(),
                prev_state_commitment: None,
            },
            body: BlockBody { transactions: vec![] },
        };
        // Main chain g(1000) -> b1(2000) -> b2(500); competing tip b1 -> c2(5000).
        assert!(store.save_block(&mk("g", 0, None, 1000)));
        assert!(store.save_block(&mk("b1", 1, Some("g"), 2000)));
        assert!(store.save_block(&mk("b2", 2, Some("b1"), 500)));
        assert!(store.save_block(&mk("c2", 2, Some("b1"), 5000)));

        let mut cache: HashMap<String, u128> = HashMap::new();
        assert_eq!(FullNode::cumulative_work_inner(&store, &mut cache, "g"), 1000);
        assert_eq!(FullNode::cumulative_work_inner(&store, &mut cache, "b1"), 3000);
        assert_eq!(FullNode::cumulative_work_inner(&store, &mut cache, "b2"), 3500);
        assert_eq!(FullNode::cumulative_work_inner(&store, &mut cache, "c2"), 8000);
        // Heaviest-chain rule: equal height (2) but c2 carries far more PoW.
        assert!(
            FullNode::cumulative_work_inner(&store, &mut cache, "c2")
                > FullNode::cumulative_work_inner(&store, &mut cache, "b2"),
            "equal-height competing tip with more PoW must have greater cumulative work"
        );
        // Memoized values are stable and consistent.
        assert_eq!(FullNode::cumulative_work_inner(&store, &mut cache, "b2"), 3500);
        assert_eq!(*cache.get("c2").unwrap(), 8000u128);
        assert_eq!(FullNode::cumulative_work_inner(&store, &mut cache, ""), 0);
    }

    #[test]
    fn confidential_gate_accepts_valid_and_rejects_tampered_block() {
        // Regression for the CRITICAL apply-path gap: recompute_virtual_chain
        // must run the full confidential gate before applying a block. This
        // tests the extracted gate function directly (no full-node harness):
        // a valid confidential tx in a block passes; a tampered one is rejected.
        use crate::config::node::node_config::NetworkMode;
        use crate::domain::block::block::Block;
        use crate::domain::block::block_body::BlockBody;
        use crate::domain::block::block_header::BlockHeader;
        use crate::domain::utxo::utxo_set::UtxoSet;
        use crate::engine::privacy::ringct::builder::{
            build_confidential_transaction, ConfRecipient, OwnedInput,
        };
        use crate::engine::privacy::ringct::dual_clsag::RingMember;
        use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
        use rand::rngs::OsRng;

        let net = NetworkMode::Mainnet;
        let h = crate::engine::privacy::confidential::pedersen::generator_h();
        let set = UtxoSet::new_empty();
        let recput = |pk: curve25519_dalek::ristretto::RistrettoPoint,
                      c: curve25519_dalek::ristretto::RistrettoPoint| {
            set.record_confidential_output_indexed(
                &hex::encode(pk.compress().as_bytes()),
                &hex::encode(c.compress().as_bytes()),
            )
            .unwrap();
        };
        for _ in 0..4 {
            recput(Scalar::random(&mut OsRng) * G, Scalar::from(9u64) * h + Scalar::random(&mut OsRng) * G);
        }
        let spend = Scalar::random(&mut OsRng);
        let bl = Scalar::random(&mut OsRng);
        let real_pk = spend * G;
        let real_c = Scalar::from(50u64) * h + bl * G;
        recput(real_pk, real_c);
        let mut ring = crate::engine::privacy::ringct::decoy::select_decoys(
            &set,
            4,
            &[hex::encode(real_pk.compress().as_bytes())],
        )
        .unwrap();
        ring.push(RingMember { public_key: real_pk, commitment: real_c });
        let real_index = ring.len() - 1;
        let vp = Scalar::random(&mut OsRng) * G;
        let sp = Scalar::random(&mut OsRng) * G;
        let tx = build_confidential_transaction(
            vec![OwnedInput { spend_secret: spend, amount: 50, blinding: bl, ring, real_index }],
            vec![ConfRecipient { view_pub: vp, spend_pub: sp, amount: 50 }],
            0,
            &net,
        )
        .unwrap();

        let mk_block = |txs: Vec<_>| Block {
            header: BlockHeader {
                version: 1,
                hash: "00".repeat(32),
                parents: vec![],
                merkle_root: String::new(),
                timestamp: 1,
                nonce: 0,
                difficulty: 1,
                height: 1,
                blue_score: 0,
                selected_parent: None,
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
                mix_hash: String::new(),
                prev_state_commitment: None,
            },
            body: BlockBody { transactions: txs },
        };

        // Valid confidential tx → gate passes.
        let good = mk_block(vec![tx.clone()]);
        assert!(verify_block_confidential_txs(&good, &set, &net).is_ok());

        // Tamper the ring signature → gate must reject the block.
        let mut bad_tx = tx.clone();
        bad_tx.inputs[0].ring_signature = Some("00".repeat(160));
        let bad = mk_block(vec![bad_tx]);
        assert!(verify_block_confidential_txs(&bad, &set, &net).is_err());
    }

    // Signature: (current_best, best_tip, current_is_tip,
    //             current_cwork, best_cwork, current_score, best_score,
    //             current_height, best_height)
    #[test]
    fn keep_current_tip_on_exact_tie_when_current_is_still_tip() {
        // Equal cumulative work, blue_score AND height → keep current (no churn).
        assert!(FullNode::should_keep_current_tip_on_tie(
            "curr", "new", true, 500, 500, 100, 100, 42, 42,
        ));
    }

    #[test]
    fn do_not_keep_current_tip_when_new_tip_is_stronger() {
        // Heavier cumulative work on the new tip → must reorg (do NOT keep).
        assert!(!FullNode::should_keep_current_tip_on_tie(
            "curr", "new", true, 500, 501, 100, 100, 42, 42,
        ));
        // Higher blue_score → do not keep.
        assert!(!FullNode::should_keep_current_tip_on_tie(
            "curr", "new", true, 500, 500, 100, 101, 42, 42,
        ));
        // Higher chain_height → do not keep.
        assert!(!FullNode::should_keep_current_tip_on_tie(
            "curr", "new", true, 500, 500, 100, 100, 42, 43,
        ));
    }

    #[test]
    fn do_not_keep_when_current_best_not_in_tip_set_or_same_tip() {
        assert!(!FullNode::should_keep_current_tip_on_tie(
            "curr", "new", false, 500, 500, 100, 100, 42, 42,
        ));
        assert!(!FullNode::should_keep_current_tip_on_tie(
            "curr", "curr", true, 500, 500, 100, 100, 42, 42,
        ));
    }
}

