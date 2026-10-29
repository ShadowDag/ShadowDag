// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// DaemonNode — The unified entry point for running a ShadowDAG node.
//
// Architecture:
//   DaemonNode owns all subsystems and wires them together:
//     ├── FullNode (block processing: validate → DAG → UTXO → store)
//     ├── P2P (network layer)
//     ├── RPC (API layer)
//     ├── Mempool (transaction pool)
//     └── Lifecycle (startup/shutdown)
//
//   ALL blocks use FullNode pipeline — no exceptions:
//     - Genesis: FullNode::process_genesis() (same pipeline, skips parent check)
//     - Regular: FullNode::process_block() (full validation + parent check)
// ═══════════════════════════════════════════════════════════════════════════

use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rocksdb::DB;

use crate::{slog_debug, slog_error, slog_info, slog_warn};

use crate::config::genesis::genesis::create_genesis_block_for;
use crate::config::node::node_config::{NetworkMode, NodeConfig};
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::engine::consensus::finality::FinalityManager;
use crate::engine::dag::core::dag_manager::DagManager;
use crate::engine::dag::ghostdag::ghostdag::GhostDag;
use crate::engine::dag::security::dag_shield::DagShield;
use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;
use crate::infrastructure::storage::rocksdb::core::db::NodeDB;
use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
use crate::runtime::node_runtime::lifecycle::Lifecycle;
use crate::service::mempool::core::mempool_manager::MempoolManager;
use crate::service::mempool::pools::tx_pool::TxPoolResult;
use crate::service::network::dos_guard::{BanCategory, MAX_TX_BYTES};
use crate::service::network::nodes::full_node::FullNode;
use crate::service::network::p2p::p2p::{
    buffer_orphan, drain_block_requests, drain_header_requests, drain_pending_blocks,
    requeue_block_requests,
    drain_pending_txs, extract_ban_ip, push_outbound, push_outbound_to_peer, report_bad_peer,
    report_bad_peer_cat, requeue_pending_blocks, requeue_pending_txs, take_orphans_for_parent,
    P2PMessage, P2P,
};
use crate::service::network::p2p::peer_manager::PeerManager;
use crate::service::network::contract_ide::ContractIdeServer;
use crate::service::network::explorer::ExplorerServer;
use crate::service::network::wallet_ui::WalletUiServer;
use crate::service::network::rpc::rpc_server::RpcServer;

use crate::engine::mining::stratum::stratum_server::{BlockTemplate, StratumServer};
use crate::errors::NodeError;
use crate::indexes::tx_index::TxIndex;
use crate::indexes::utxo_index::UtxoIndex;

/// Sentinel substrings used to classify block-rejection errors.
/// Centralised here so a single rename propagates to every check.
/// IMPORTANT: these are compared against `.to_lowercase()` error strings,
/// so they MUST be lowercase to ensure case-insensitive matching.
const ERR_ALREADY_EXISTS: &str = "already exists";
const ERR_ORPHAN: &str = "orphan";
const ERR_DIFFICULTY_RANGE: &str = "outside allowed range";
const ERR_DIFFICULTY_MISMATCH: &str = "difficulty mismatch";
const ERR_STALE_TEMPLATE: &str = "stale template";

/// Whether an orphan block is worth resolving — i.e. we should fetch its missing
/// parents and buffer it for reprocessing. True for any orphan within
/// FINALITY_DEPTH of our tip, INCLUDING a competing chain at the SAME height:
/// that is exactly what a node stuck on a side-branch tip must download to switch
/// to the heavier chain and converge. Ancient orphans (deeper than the finality
/// window below our tip) can never reorg us, so they are ignored (anti-thrash for
/// old forks). A strict `orphan_height > best_height` gate silently broke
/// convergence: a side-branch-stuck node fetched the canonical sibling, failed to
/// place it, dropped it, and looped forever.
#[inline]
fn orphan_worth_resolving(orphan_height: u64, best_height: u64) -> bool {
    use crate::engine::consensus::reorg::FINALITY_DEPTH;
    // Resolve (fetch missing parents + buffer) only orphans within the reorg
    // window on BOTH sides of our tip:
    //   • not deeper than FINALITY_DEPTH below the tip (anti-thrash for old forks)
    //   • not further than FINALITY_DEPTH ABOVE the tip.
    // The upper bound is the W2 fix: a FAR-ahead orphan must be reached by
    // FORWARD header-sync (batched, in order), NOT a backward orphan-walk —
    // that walk is O(gap) round-trips and, for a far-behind node joining a tall
    // chain, floods the event loop (each orphan re-requests its parent), which
    // starves forward header-sync so the node never catches up. A far-ahead
    // block also can't reorg us (that needs a > MAX_REORG_DEPTH rollback, which
    // is rejected regardless), so orphan-walking toward it is pure waste.
    orphan_height.saturating_add(FINALITY_DEPTH) > best_height
        && orphan_height <= best_height.saturating_add(FINALITY_DEPTH)
}

/// How far above our tip a gossiped block must be before we drop it CHEAPLY
/// instead of running full validation + orphan buffering on it. Comfortably
/// above FINALITY_DEPTH (the reorg-competitor window) and the header-sync
/// batch size, so genuine competing tips and requested catch-up blocks are
/// NEVER dropped.
const FAR_FUTURE_GOSSIP_WINDOW: u64 = crate::engine::consensus::reorg::FINALITY_DEPTH * 4;

/// Whether a gossiped block is so far above our tip that processing it now is
/// pure waste. Such a block cannot connect (its ancestors are far ahead) and
/// is NOT a reorg competitor (those sit within FINALITY_DEPTH). Header-sync
/// backfills the gap IN ORDER, so dropping the far-future flood cheaply keeps
/// the event loop free for header-sync. Without this, a far-behind node burns
/// all its CPU validating+rejecting gossip (a flood that grows with chain
/// height) and never catches up — the reproduced "a new node cannot join a
/// tall chain" convergence blocker.
#[inline]
fn is_far_future_gossip(block_height: u64, best_height: u64) -> bool {
    block_height > best_height.saturating_add(FAR_FUTURE_GOSSIP_WINDOW)
}

#[inline]
fn is_transient_block_rejection(err_msg_lc: &str) -> bool {
    err_msg_lc.contains(ERR_DIFFICULTY_RANGE)
        || err_msg_lc.contains(ERR_DIFFICULTY_MISMATCH)
        || err_msg_lc.contains(ERR_STALE_TEMPLATE)
}

#[inline]
fn is_non_penalized_block_rejection(err_msg_lc: &str) -> bool {
    err_msg_lc.contains(ERR_ALREADY_EXISTS)
        || err_msg_lc.contains(ERR_ORPHAN)
        || is_transient_block_rejection(err_msg_lc)
        || err_msg_lc.contains("peer is banned")
        || err_msg_lc.contains("rate_limited")
        || err_msg_lc.contains("dos_rejected")
}

/// Walk our chain FORWARD from the requester's tip and collect up to `count`
/// block hashes for a Headers reply, so a behind/forked peer can bulk-download
/// and converge (far faster than the sequential orphan-walk).
///
/// `from_height` is the height of the requester's `from_hash` in OUR store
/// (None if we have never seen it). The walk begins AT that height — NOT one
/// past it — so a forked requester also receives the canonical SIBLING(s) at
/// its own tip height: the block it must adopt to heal a one-block fork. Under
/// the old `from_height + 1` start the sibling was never served, and a node
/// stuck on a side-branch tip could only heal via the slow orphan-walk (or not
/// at all when the relaying peer lacked the ancestor). `from_hash` itself is
/// skipped (the requester already has it). When `from_hash` is unknown we serve
/// from genesis (height 1) so a forked peer receives our whole chain.
///
/// `at_height` yields every block hash we store at a given height (both DAG
/// branches). Bounded to 512 hashes; stops at the first empty height (our tip).
fn collect_forward_headers(
    from_hash: &str,
    from_height: Option<u64>,
    count: u32,
    mut at_height: impl FnMut(u64) -> Vec<String>,
) -> Vec<String> {
    let start = from_height.unwrap_or(1);
    let want = (count as usize).clamp(1, 512);
    let mut hashes: Vec<String> = Vec::with_capacity(want);
    let mut h = start;
    while hashes.len() < want {
        let at = at_height(h);
        if at.is_empty() {
            break; // reached our tip
        }
        for hh in at {
            if hh == from_hash {
                continue; // requester already has its own tip
            }
            hashes.push(hh);
            if hashes.len() >= want {
                break;
            }
        }
        h += 1;
    }
    hashes
}

/// Event-loop idle sleep. At module scope because `HEADER_SERVE_INTERVAL` is
/// defined in terms of it.
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// One header-serve pass's budget, in the three dimensions a request can be
/// expensive in: how many requests, how much chain walking, and how many
/// hashes go back out.
///
/// The loop used to serve the WHOLE drained queue — up to
/// `MAX_HEADER_REQUEST_QUEUE` = 2,000 entries, each walking up to 512
/// `get_block_hashes_at_height` prefix iterators and replying with 36,889
/// bytes. That is ~1.02M iterators and ~74 MB of outbound in one pass of this
/// single-threaded loop, for ~58 KB of requests. The block-serve branch has
/// had a per-tick bound all along.
///
/// All three are needed. A near-tip request walks one height and sends a few
/// hashes; a from-genesis request walks 512 and sends 36,889 bytes; a request
/// pointed past our tip walks one and sends nothing but still costs a lookup
/// and a log line. And heights do not bound bytes: `collect_forward_headers`
/// takes EVERY hash at a visited height, so a DAG w blocks wide yields w
/// hashes per height.
///
/// Rate: `HEADER_SERVE_INTERVAL` below turns these per-pass numbers into
/// per-second ones — 5,120 requests/s, 163,840 walked heights/s and 163,840
/// hashes/s (~11.8 MB/s of egress). Honest demand for comparison: a peer asks
/// once per `sync_interval` (6 s), or twice a second while catching up, so
/// MAX_PEERS = 64 peers all catching up at once want ~128 requests/s and
/// ~65,500 of both heights and hashes per second — 40% of either budget. The
/// rate-ceiling test holds BOTH expensive dimensions to 2x that storm; heights
/// used to sit at 1.25x, which is not headroom. Requests past the budget are
/// dropped, not requeued: the requester re-asks on its next interval, and
/// requeueing would let a flooder's backlog head-of-line block the peers
/// behind it.
const MAX_HEADER_SERVES_PER_TICK: usize = 256;
const MAX_HEADER_HEIGHTS_PER_TICK: usize = 8_192;
const MAX_HEADER_HASHES_PER_TICK: usize = 8_192;

/// Minimum wall-clock gap between header-serve passes.
///
/// Without it the per-pass budget bounded nothing per second: the loop sleeps
/// only `if !did_work`, and a non-empty header queue sets `did_work`, so a
/// peer that keeps asking suppresses the sleep and every spin re-grants the
/// full budget. The spin period was then set by how long the budget's own work
/// took — which is the opposite of a rate limit. Same shape as
/// `last_sync_req`/`sync_interval` in this loop.
const HEADER_SERVE_INTERVAL: std::time::Duration = POLL_INTERVAL;

/// Block-serve requests processed per pass.
///
/// Counts requests PROCESSED, not blocks found: a request for a hash we do not
/// have still costs a RocksDB point lookup, and the old counter only advanced
/// on a hit, so a flood of unknown hashes was unbounded work per pass.
///
/// Sized ABOVE the honest per-host burst, as the header budget is: a peer
/// catching up answers one Headers reply with up to `MAX_BLOCK_REQUESTS_PER_IP`
/// GetBlock messages, and a budget BELOW that would mean a normal sync round
/// could never be served in one pass. The bytes budget below is what actually
/// bounds the heavy case; this one only stops a flood of cheap misses from
/// monopolising a pass.
const MAX_BLOCK_SERVES_PER_TICK: usize = 256;

/// Bytes of block serialized per pass. The dimension that actually matters
/// here: a block runs to MAX_BLOCK_BYTES, so 512 of them was up to a gigabyte
/// of read-plus-serialize in one turn of the loop, and all of it lands in
/// TARGETED_MSGS, which has no byte bound of its own.
///
/// Sized so one maximum block always gets through — the budget is checked
/// before a request is served, so progress cannot stall on an oversized block.
/// Whatever a pass cannot reach is requeued, not dropped, so this is a rate
/// limit rather than a ceiling on what a sync round can ever receive.
const MAX_BLOCK_SERVE_BYTES_PER_TICK: usize = 2 * 1024 * 1024;

/// Minimum wall-clock gap between block-serve passes. Without it the per-pass
/// numbers above are not a rate: `did_work` suppresses the loop's only sleep
/// for as long as requests keep arriving.
const BLOCK_SERVE_INTERVAL: std::time::Duration = POLL_INTERVAL;

/// Whether a header-serve pass is due.
///
/// Extracted so the pacing is checkable: it is the only thing that turns the
/// per-pass budget below into a per-second bound, and the event loop it guards
/// cannot be unit-tested.
fn header_pass_due(since_last_pass: std::time::Duration) -> bool {
    since_last_pass >= HEADER_SERVE_INTERVAL
}

/// Whether enough time has passed to run another block-serve pass.
fn block_pass_due(since_last_pass: std::time::Duration) -> bool {
    since_last_pass >= BLOCK_SERVE_INTERVAL
}

/// Whether this block-serve pass has spent its budget.
fn block_budget_spent(served: usize, bytes: usize) -> bool {
    served >= MAX_BLOCK_SERVES_PER_TICK || bytes >= MAX_BLOCK_SERVE_BYTES_PER_TICK
}

/// Whether this pass's header-serve budget is spent.
///
/// `served` counts requests PROCESSED, not replies sent — a walk that found
/// nothing still cost a store lookup and a log line.
fn header_budget_spent(served: usize, walked_heights: usize, hashes: usize) -> bool {
    served >= MAX_HEADER_SERVES_PER_TICK
        || walked_heights >= MAX_HEADER_HEIGHTS_PER_TICK
        || hashes >= MAX_HEADER_HASHES_PER_TICK
}

/// Order header-serve requests round-robin by key, starting the rotation at
/// host `start_host`: every key's first request, then every key's second, and
/// so on, stable within each round.
///
/// Round-robin alone equalises request COUNT, not COST, and the budget it
/// feeds is shared: eight from-genesis walks spend a whole pass, so the hosts
/// behind them are dropped. A flooder keeps a request queued at all times and
/// would therefore lead every pass, which is the starvation class this
/// ordering claims to prevent. `start_host` rotates the lead, so every host
/// with a queued request is reached within ceil(hosts / served-per-pass)
/// passes — about 100 ms for the numbers above.
///
/// The caller keys on the source IP, not on `ip:port`: the share belongs to
/// the host, exactly as the queue quota does, or one host's
/// `MAX_PEERS_PER_IP` sockets would take that many leading slots.
fn round_robin_by_peer<T: AsRef<str>>(peers: &[T], start_host: usize) -> Vec<usize> {
    let mut slot_of: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    let mut per_host: Vec<Vec<usize>> = Vec::new();
    for (i, peer) in peers.iter().enumerate() {
        let key = peer.as_ref();
        let slot = match slot_of.get(key) {
            Some(s) => *s,
            None => {
                per_host.push(Vec::new());
                let s = per_host.len() - 1;
                slot_of.insert(key, s);
                s
            }
        };
        per_host[slot].push(i);
    }
    let hosts = per_host.len();
    if hosts == 0 {
        return Vec::new();
    }
    let deepest = per_host.iter().map(|v| v.len()).max().unwrap_or(0);
    let mut out = Vec::with_capacity(peers.len());
    // Reduced first, so the sum below cannot overflow for a long-lived cursor.
    let lead = start_host % hosts;
    for round in 0..deepest {
        for offset in 0..hosts {
            if let Some(&i) = per_host[(lead + offset) % hosts].get(round) {
                out.push(i);
            }
        }
    }
    out
}

/// Ban score for peers that send invalid blocks rejected by consensus.
const BAN_SCORE_INVALID_BLOCK: u64 = 20;
/// Ban score for peers that send invalid transactions rejected by mempool.
const BAN_SCORE_INVALID_TX: u64 = 5;

pub struct DaemonNode {
    cfg: NodeConfig,
    db: Arc<DB>,
    /// The unified block processing engine — ALL block operations go through here
    full_node: Arc<FullNode>,
    /// Direct access to stores (for genesis init + RPC)
    block_store: Arc<BlockStore>,
    utxo_set: Arc<UtxoSet>,
    dag: Arc<DagManager>,
    ghostdag: Arc<GhostDag>,
    peer_manager: Arc<PeerManager>,
    mempool: Arc<Mutex<MempoolManager>>,
    /// UTXO index (in-memory cache backed by RocksDB)
    utxo_index: Arc<Mutex<UtxoIndex>>,
    /// TX index (in-memory cache backed by RocksDB)
    tx_index: Arc<Mutex<TxIndex>>,
    /// Dynamic finality manager — adjusts finality depth based on DAG health
    finality_manager: Mutex<FinalityManager>,
    /// Contract storage for smart contract deployment and state
    contract_storage: Arc<crate::runtime::vm::contracts::contract_storage::ContractStorage>,
    /// Optional Stratum V1 mining pool server (enabled via --enable-stratum)
    stratum_server: Option<Arc<StratumServer>>,
}

impl DaemonNode {
    pub fn new(cfg: NodeConfig) -> Result<Self, NodeError> {
        // Use network-specific data directory to prevent cross-network contamination
        let db_path = cfg.data_dir.join("db");
        let db_path_str = db_path.to_string_lossy().to_string();
        let node_db = NodeDB::new(&db_path_str).map_err(|e| NodeError::Init(e.to_string()))?;
        let db = node_db.shared();

        let dag = match DagManager::new(db.clone()) {
            Some(d) => Arc::new(d),
            None => {
                return Err(NodeError::Init(format!(
                    "[daemon] FATAL: cannot create DAG manager at {}",
                    db_path_str
                )));
            }
        };

        let block_store = Arc::new(BlockStore::new(db.clone()).map_err(|e| {
            NodeError::Init(format!("[daemon] FATAL: cannot create block store: {}", e))
        })?);

        let utxo_store = Arc::new(UtxoStore::new(db.clone()).map_err(|e| {
            NodeError::Init(format!("[daemon] FATAL: cannot create UTXO store: {}", e))
        })?);
        let utxo_set = Arc::new(
            UtxoSet::new(
                utxo_store.clone() as Arc<dyn crate::domain::traits::utxo_backend::UtxoBackend>,
            )
            .with_network(cfg.network.clone()),
        );

        // GhostDag shares the node's single RocksDB instance.
        // All GhostDag keys are namespaced with "gd:" to avoid collisions.
        let ghostdag = Arc::new(GhostDag::new_with_db(db.clone()));

        let peer_manager = Arc::new(
            PeerManager::new_default_path(&cfg.peers_path_str())
                .map_err(|e| NodeError::Init(format!("Failed to init peer manager: {}", e)))?,
        );

        let mempool = Arc::new(Mutex::new(
            MempoolManager::new_with_peer_manager(db.clone(), peer_manager.clone())
                .map_err(|e| NodeError::Init(format!("Failed to init mempool: {}", e)))?,
        ));

        // Open persistent contract storage (from ~/.shadowdag/<network>/contracts/).
        // Path MUST be valid UTF-8 — we never silently fall back to a relative
        // "contracts" string because that would create a second on-disk database
        // in the current working directory, divorced from the real data dir.
        let contract_path_buf = cfg.contract_path();
        let contract_path_str = contract_path_buf.to_str().ok_or_else(|| {
            NodeError::Init(format!(
                "[daemon] FATAL: contract path is not valid UTF-8: {:?}. \
                 Refusing to fall back to a relative path that could split state \
                 across two directories. Fix the data directory path and restart.",
                contract_path_buf
            ))
        })?;
        let contract_storage = Arc::new(
            crate::runtime::vm::contracts::contract_storage::ContractStorage::new(
                contract_path_str,
            )
            .map_err(|e| {
                NodeError::Init(format!("[daemon] contract storage init failed: {}", e))
            })?,
        );

        // Create the unified block processing engine
        let full_node = Arc::new(FullNode::new(
            block_store.clone(),
            utxo_set.clone(),
            dag.clone(),
            ghostdag.clone(),
            cfg.network.clone(),
            contract_storage.clone(),
        ));

        // Initialize persistent indexes with shared DB (auto-recovers from disk)
        let utxo_index = Arc::new(Mutex::new(UtxoIndex::new_with_db(db.clone())));
        let tx_index = Arc::new(Mutex::new(TxIndex::new_with_db(db.clone())));

        // Initialize dynamic finality manager (10 BPS default)
        let mut finality_mgr = FinalityManager::new(10);
        finality_mgr = finality_mgr.with_db(db.clone());
        finality_mgr.load_checkpoints();

        // Initialize Stratum pool server if enabled.
        // FORK/M5 GUARD (H2 + M5): the built-in Stratum pool hashes ShadowHash only,
        // emits version-2 templates (build_stratum_template), and stamps
        // prev_state_commitment = None in every header it hashes and submits. Such a
        // block is rejected TWICE: by the UmbraHash consensus floor on umbra-fork
        // networks (mainnet: PowValidator::validate_for_network), and by the M5
        // deferred-state-commitment verify on EVERY network (enforced for height>0,
        // network-agnostic — the pool cannot supply the node-published commitment).
        // Until a UmbraHash + M5-aware Stratum hashing path exists, refuse to run a
        // dead pool: disable it (loud warning) rather than mine blocks the network
        // will reject. The solo/docker miner (bin/miner.rs — forces version 3 and
        // stamps the node-published prev_state_commitment) is the mining path on
        // every network.
        let stratum_server = if cfg.enable_stratum {
            slog_warn!("daemon", "stratum_disabled_incompatible",
                network => cfg.network.name(),
                reason => "built-in Stratum pool is ShadowHash-only and pre-M5 (None commitment); UmbraHash and the M5 state commitment are mandatory — use the UmbraHash solo/docker miner");
            None
        } else {
            None
        };

        Ok(Self {
            cfg,
            db,
            full_node,
            block_store,
            utxo_set,
            dag,
            ghostdag,
            peer_manager,
            mempool,
            utxo_index,
            tx_index,
            finality_manager: Mutex::new(finality_mgr),
            contract_storage,
            stratum_server,
        })
    }

    pub fn mainnet() -> Result<Self, NodeError> {
        Self::new(NodeConfig::for_network(NetworkMode::Mainnet))
    }
    pub fn testnet() -> Result<Self, NodeError> {
        Self::new(NodeConfig::for_network(NetworkMode::Testnet))
    }
    pub fn regtest() -> Result<Self, NodeError> {
        Self::new(NodeConfig::for_network(NetworkMode::Regtest))
    }

    pub fn start(&mut self) -> Result<(), NodeError> {
        // No-op unless built with `deadlock-detect`. Present unconditionally so
        // a diagnostic build needs no source change — only a feature flag.
        crate::telemetry::deadlock_watch::spawn();

        Lifecycle::on_start();
        self.print_banner();

        // ── Genesis initialization (idempotent, fail-closed) ─────
        //
        // CRITICAL: we MUST distinguish "no chain yet" (safe to init genesis)
        // from "read error / corrupt best_hash" (unsafe — aborting the process
        // is the only correct response, because re-initializing genesis over an
        // existing but unreadable chain would wipe the UTXO set and all blocks).
        //
        // `get_best_hash_strict()` collapses the three states correctly:
        //   Ok(None)    → key genuinely absent → init genesis
        //   Ok(Some(h)) → chain present → recover + resume
        //   Err(_)      → corrupt / read failure → FATAL, refuse to proceed
        let existing_best = self.block_store.get_best_hash_strict().map_err(|e| {
            NodeError::Init(format!(
                "[daemon] FATAL: refusing to start — could not read best_hash from \
                 BlockStore: {}. This typically means on-disk state is corrupt or \
                 RocksDB is unreadable. Do NOT proceed to genesis initialization \
                 (that would wipe any existing chain). Investigate the data \
                 directory, restore from backup, or use --reindex if appropriate.",
                e
            ))
        })?;

        if existing_best.is_none() {
            let genesis = create_genesis_block_for(&self.cfg.network);
            slog_info!("daemon", "genesis_hash", hash => genesis.header.hash);

            // Genesis goes through FullNode::process_genesis() — SAME pipeline
            // as all other blocks (validate, save, DAG, GHOSTDAG, UTXO, best_hash).
            // Only difference: parent validation skipped (genesis has no parents).
            self.full_node.process_genesis(&genesis).map_err(|e| {
                NodeError::Init(format!("[daemon] FATAL: genesis processing failed: {}", e))
            })?;
            slog_info!("daemon", "genesis_created");
        } else {
            slog_info!("daemon", "existing_chain_found", best => existing_best.as_deref().unwrap_or_default());

            // === CRASH RECOVERY (3-level verification) ===
            // Level 1: BlockStore integrity (best hash + block exist)
            // Level 2: DAG consistency (DAG knows best block, rebuild if not)
            // Level 3: UTXO integrity (expected vs actual count, full replay if mismatch)
            self.verify_and_recover().map_err(|e| {
                NodeError::Init(format!("[daemon] FATAL: crash recovery failed: {}", e))
            })?;

            // After recovery: don't trust cached best_tip.
            // Recompute GHOSTDAG ordering to ensure consistent state.
            // FATAL if this fails — continuing with stale virtual chain means
            // the UTXO set, DAG tip, and block template are all inconsistent.
            slog_info!("daemon", "recomputing_virtual_chain");
            self.full_node.recompute_virtual_chain().map_err(|e| {
                NodeError::Init(format!(
                    "[daemon] FATAL: virtual chain recompute failed: {}. \
                     UTXO state is potentially inconsistent — refusing to start. \
                     Try --reindex or delete the data directory to force full rebuild.",
                    e
                ))
            })?;
        }

        // M5 (restart halt fix): republish the mining template over the FINAL
        // post-recovery canonical state, unconditionally, before RPC/P2P start.
        // FullNode::new seeded the mining cells from the DAG at construction (BEFORE
        // verify_and_recover possibly rebuilt a corrupt DAG), and
        // recompute_virtual_chain early-returns without republishing when the
        // recomputed best equals the persisted best (the normal restart case). Under
        // M5 a stale commitment makes getblocktemplate serve a value the height>=1
        // validator rejects — a block-production halt on this node. This one call
        // guarantees the cells reflect the settled tips. Idempotent on the fresh
        // path (process_genesis already published the same value).
        self.full_node.republish_mining_template();

        // ── P2P ──────────────────────────────────────────────────
        let mut p2p = P2P::new_with_config_and_peers(&self.cfg, self.peer_manager.clone())?;
        p2p.peers.bootstrap_for_network(&self.cfg.network);
        // Explicit --connect peers (local testing / private deployments).
        for addr in &self.cfg.connect_peers {
            match p2p.peers.add_peer(addr) {
                Ok(()) => slog_info!("daemon", "connect_peer_added", addr => addr),
                Err(e) => slog_warn!("daemon", "connect_peer_invalid", addr => addr, error => &e.to_string()),
            }
        }
        let discovered = p2p.peers.discover_peers();
        if discovered.is_empty() {
            slog_warn!("daemon", "peer_discovery_returned_empty",
                note => "no peers found — node may be isolated until inbound connections arrive");
        }
        slog_info!("daemon", "p2p_bootstrapped", peers => p2p.peers.count());

        // ── RPC ──────────────────────────────────────────────────
        let rpc = RpcServer::new_for_network_with_peer_manager(
            self.cfg.rpc_port,
            self.peer_manager.clone(),
            self.db.clone(),
            Some(&self.cfg.data_dir),
        )
        .map_err(|e| NodeError::Init(format!("Failed to init RPC server: {}", e)))?;
        rpc.set_network_name(self.cfg.network.name());
        rpc.set_network_ports(self.cfg.p2p_port, self.cfg.rpc_port);
        // Wire the real network into the RPC's UTXO set + mempool so coinbase
        // maturity and tx validation match the active chain (they default to
        // Mainnet otherwise — see RpcServer::set_network_mode).
        rpc.set_network_mode(self.cfg.network.clone());
        rpc.set_contract_storage(Arc::clone(&self.contract_storage));
        rpc.start()
            .map_err(|e| NodeError::Init(format!("RPC start failed: {}", e)))?;
        slog_info!("daemon", "rpc_started", port => self.cfg.rpc_port);

        // ── Start network ────────────────────────────────────────
        p2p.start()
            .map_err(|e| NodeError::Init(format!("P2P start failed: {}", e)))?;
        slog_info!("daemon", "p2p_listening", addr => p2p.listen_addr);

        // ── Stratum pool ─────────────────────────────────────────
        if let Some(ref stratum) = self.stratum_server {
            // Register with RPC so getpoolstats can read live data
            crate::service::network::rpc::rpc_server::register_stratum(Arc::clone(stratum));
            let stratum_clone = Arc::clone(stratum);
            std::thread::spawn(move || {
                stratum_clone.start();
            });
            slog_info!("daemon", "stratum_started", port => self.cfg.stratum_port);
            if self.cfg.stratum_address.is_none() {
                slog_warn!("daemon", "stratum_no_payout_address",
                    hint => "set --stratum-address=<SD1...> so the pool can produce payable blocks");
            }
        }

        // ── Explorer web UI ────────────────────────────────────────
        if self.cfg.enable_explorer {
            // The explorer shares the same RpcState the RPC server uses,
            // giving it direct access to BlockStore, UtxoSet, Mempool, etc.
            let explorer_state = rpc.shared_state();
            let explorer = ExplorerServer::new(self.cfg.explorer_port, explorer_state);
            explorer
                .start()
                .map_err(|e| NodeError::Init(format!("Explorer start failed: {}", e)))?;
            slog_info!("daemon", "explorer_started", port => self.cfg.explorer_port);
        }

        // ── Wallet Web UI ─────────────────────────────────────────
        if self.cfg.enable_wallet_ui {
            let wallet_state = rpc.shared_state();
            let wallet_ui = WalletUiServer::new(self.cfg.wallet_ui_port, wallet_state);
            wallet_ui
                .start()
                .map_err(|e| NodeError::Init(format!("Wallet UI start failed: {}", e)))?;
            slog_info!("daemon", "wallet_ui_started", port => self.cfg.wallet_ui_port);
        }

        // ── Contract IDE ──────────────────────────────────────────
        if self.cfg.enable_ide {
            let ide = ContractIdeServer::new(self.cfg.ide_port, self.cfg.rpc_port);
            ide.start()
                .map_err(|e| NodeError::Init(format!("IDE start failed: {}", e)))?;
            slog_info!("daemon", "ide_started", port => self.cfg.ide_port);
        }

        slog_info!("daemon", "node_running", network => self.cfg.network.name());

        Ok(())
    }

    // ── Event Loop ─────────────────────────────────────────────

    /// The main event loop. Drains P2P pending queues, processes blocks
    /// through the full consensus pipeline, and adds transactions to the
    /// mempool. This is the heartbeat of the node — without it, P2P data
    /// piles up in queues and is never processed.
    ///
    /// Handles Ctrl+C gracefully to allow RocksDB to flush before exit.
    pub fn run_event_loop(&self) {
        use std::time::{Duration, Instant};

        const STATS_INTERVAL: Duration = Duration::from_secs(30);
        const FLUSH_INTERVAL: Duration = Duration::from_secs(15);
        const TX_BATCH_LIMIT: usize = 500; // Max TXs per tick (backpressure)
        const BLOCK_BATCH_LIMIT: usize = 50; // Max blocks per tick

        // Register Ctrl+C handler for graceful shutdown
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_flag = shutdown.clone();
        if let Err(e) = ctrlc::set_handler(move || {
            slog_info!("daemon", "shutdown_signal_received");
            shutdown_flag.store(true, Ordering::SeqCst);
        }) {
            slog_warn!("daemon", "ctrlc_handler_failed", error => e);
        }

        let mut last_stats = Instant::now();
        let mut last_flush = Instant::now();
        let mut last_sync_req = Instant::now();
        let mut last_header_serve = Instant::now();
        let mut last_block_serve = Instant::now();
        // Which host leads the next header-serve pass. Advanced by what the
        // pass served, so a flooder cannot lead every pass.
        let mut header_rr_cursor = 0usize;
        // Rotating lead for the block-serve order, for the same reason.
        let mut block_rr_cursor = 0usize;
        // While catching up, request the next header range every 500ms instead of
        // the idle 6s cadence so the download pipeline stays full. Extended 5s on
        // every tick that applies blocks; lapses back to 6s once caught up.
        let mut fast_sync_until = Instant::now();
        let mut total_blocks_processed: u64 = 0;
        let mut total_txs_processed: u64 = 0;
        let mut total_blocks_rejected: u64 = 0;
        let mut total_txs_rejected: u64 = 0;

        slog_info!("daemon", "event_loop_started", poll_interval_ms => POLL_INTERVAL.as_millis());

        while !shutdown.load(Ordering::SeqCst) {
            let mut did_work = false;

            // ── Periodic chain-sync request ─────────────────────────
            // Ask peers for headers forward of our best block so a behind or
            // freshly-reconnected node catches up even without a gossip trigger.
            // Peers walk their chain from our best_hash and reply (Headers ->
            // GetBlock -> Block). If we forked, they don't have our best_hash and
            // serve from genesis, so we download their chain and GHOSTDAG adopts
            // the higher-blue-score one.
            let sync_interval = if Instant::now() < fast_sync_until {
                std::time::Duration::from_millis(500)
            } else {
                std::time::Duration::from_secs(6)
            };
            if last_sync_req.elapsed() >= sync_interval {
                last_sync_req = Instant::now();
                let from_hash = self.block_store.get_best_hash().unwrap_or_default();
                slog_info!("daemon", "header_sync_request_sent",
                    from => from_hash.get(..16).unwrap_or(&from_hash));
                push_outbound(P2PMessage::GetHeaders {
                    from_hash,
                    count: 512,
                });
            }

            // ── Drain pending blocks (peer-tagged) ─────────────────
            // Take only BLOCK_BATCH_LIMIT items; return excess to the queue
            // so they're processed on the next tick (no message loss under load).
            let mut blocks = drain_pending_blocks();
            // Process in HEIGHT ORDER (W1). Blocks arrive out of order — a peer
            // serves a whole 512-block range concurrently, so height 11 can land
            // before height 10. Applying 11 first makes it a needless orphan
            // (parent 10 not yet applied), which cascades into an orphan-pool
            // flood that starves IBD catch-up. Sorting the batch by height, and
            // keeping the LOWEST via split_off, means each block's parent is
            // applied before it, so the requested range connects in sequence
            // with no orphan churn. Cheap for the near-tip case (few blocks).
            blocks.sort_by_key(|(_, b)| b.header.height);
            let excess_blocks = if blocks.len() > BLOCK_BATCH_LIMIT {
                blocks.split_off(BLOCK_BATCH_LIMIT)
            } else {
                Vec::new()
            };
            if !excess_blocks.is_empty() {
                requeue_pending_blocks(excess_blocks);
            }
            if !blocks.is_empty() {
                did_work = true;
                // Were we already in catch-up before this batch? (Captured BEFORE
                // extending the window below.) Used to suppress re-gossip of IBD
                // backfill further down.
                let was_catching_up = Instant::now() < fast_sync_until;
                fast_sync_until = Instant::now() + std::time::Duration::from_secs(5);
                let batch_start = std::time::Instant::now();
                let mut processed_count = 0usize;
                let mut seen_hashes: std::collections::HashSet<String> =
                    std::collections::HashSet::with_capacity(blocks.len());
                // Missing-parent hashes already requested this drain — avoids
                // re-broadcasting the same GetBlock when several orphans in one
                // batch share an ancestor.
                let mut requested_parents: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                // Whether any block was accepted this batch → fsync the WAL once
                // at the end (durable block-commit boundary).
                let mut accepted_this_batch = false;
                // Our tip height at batch start, for the far-future-gossip gate.
                // Computed once (a lower bound — accepting blocks this batch only
                // raises the real tip, making the gate strictly more permissive).
                let batch_best_height = self
                    .block_store
                    .get_best_hash()
                    .and_then(|h| self.block_store.get_block_height(&h))
                    .unwrap_or(0);
                let mut far_future_dropped = 0u64;
                for (peer_id, block) in blocks.iter() {
                    // Skip duplicate hashes within the same drained batch.
                    // Multiple peers may relay the same block nearly simultaneously.
                    // Processing it once is sufficient; extra attempts only create
                    // noisy "already exists"/stale errors and unnecessary CPU load.
                    if !seen_hashes.insert(block.header.hash.clone()) {
                        processed_count += 1;
                        continue;
                    }
                    let hash_prefix = block.header.hash.get(..16).unwrap_or(&block.header.hash);

                    // ── DagShield safety net (defense-in-depth) ──
                    // P2P dispatch already calls pre_validate_block, but the event
                    // loop is the LAST gate before FullNode — catch anything that
                    // slipped through (e.g. RPC-submitted blocks, future code paths).
                    if let Err(rej) = DagShield::pre_validate_block(block) {
                        total_blocks_rejected += 1;
                        report_bad_peer(peer_id, rej.ban_score as u64, rej.reason);
                        slog_warn!("daemon", "block_rejected_dagshield", hash => hash_prefix, reason => rej.reason);
                        processed_count += 1;
                        continue;
                    }

                    // ── Far-future gossip gate (anti-flood, pro-convergence) ──
                    // Drop CHEAPLY (no validation, no orphan buffering, no ban)
                    // any gossiped block far above our tip: it can't connect and
                    // isn't a reorg competitor; header-sync backfills the gap in
                    // order. This keeps the loop free for header-sync so a
                    // far-behind node can actually catch up to a tall chain.
                    if is_far_future_gossip(block.header.height, batch_best_height) {
                        far_future_dropped += 1;
                        processed_count += 1;
                        continue;
                    }

                    match self.full_node.process_block_from_peer(block, peer_id) {
                        Ok(()) => {
                            total_blocks_processed += 1;
                            accepted_this_batch = true;
                            slog_info!("daemon", "block_processed", hash => hash_prefix, height => block.header.height, txs => block.body.transactions.len());

                            // Notify finality manager with real DAG data
                            let is_blue = self.ghostdag.get_blue_score(&block.header.hash) > 0;
                            let dag_width =
                                self.block_store.blocks_at_height(block.header.height) as u64;
                            self.finality_manager.lock().on_block(
                                block.header.height,
                                &block.header.hash,
                                is_blue,
                                dag_width.max(1),
                            );

                            // Evict mined txs from the mempool (with dependents).
                            // CONSENSUS-CRITICAL: without this a confirmed tx
                            // stays pooled forever and is re-included in every
                            // future template; execution then skips it as a
                            // duplicate (ZERO fees), so every coinbase claiming
                            // its fee is invalid and followers reject the whole
                            // chain from that block on (testnet froze at 1659).
                            //
                            // Evict ONLY txs actually applied on the SELECTED
                            // chain — those with a tx_seen marker (self.utxo_set
                            // shares full_node's store). A block returning Ok is
                            // merely ACCEPTED INTO THE DAG; a losing side-branch
                            // block's txs were never applied, so evicting them by
                            // raw block-body membership would silently drop
                            // still-unconfirmed txs from this node's mempool with
                            // no reorg re-injection (a censorship/liveness gap).
                            // This mirrors the is_tx_seen template filter, so
                            // eviction and template selection stay consistent.
                            let confirmed: Vec<String> = block
                                .body
                                .transactions
                                .iter()
                                .filter(|t| !t.is_coinbase())
                                .filter(|t| self.utxo_set.is_tx_seen(&t.hash))
                                .map(|t| t.hash.clone())
                                .collect();
                            if !confirmed.is_empty() {
                                self.mempool
                                    .lock()
                                    .on_new_block(block.header.height, &confirmed);
                            }

                            // Broadcast accepted block to peers (gossip propagation).
                            // Skip while catching up (IBD backfill): re-gossiping the
                            // thousands of blocks we just pulled floods our own
                            // OUTBOUND_MSGS queue, which starves GetHeaders and stalls
                            // sync. Peers fetch the backlog via their own header-sync;
                            // a caught-up node still relays genuinely new tips.
                            if !was_catching_up {
                                if let Ok(block_bytes) = bincode::serialize(block) {
                                    push_outbound(P2PMessage::Block { data: block_bytes });
                                }
                            }

                            // Chain sync: any orphan that was waiting on THIS block
                            // as a parent may now connect — requeue it so it is
                            // reprocessed this pass. This is how a node walks a
                            // downloaded ancestor chain forward and adopts it.
                            let ready = take_orphans_for_parent(&block.header.hash);
                            if !ready.is_empty() {
                                requeue_pending_blocks(ready);
                            }

                            // Notify Stratum pool with a fresh, VALID block
                            // template (real coinbase + merkle root) so pool
                            // miners produce acceptable blocks. Skipped silently
                            // when no payout address is configured (warned once
                            // at startup).
                            if let Some(ref stratum) = self.stratum_server {
                                let job_id = format!("{:x}", total_blocks_processed);
                                if let Some(template) = self.build_stratum_template(block, job_id) {
                                    stratum.update_template(template);
                                }
                            }
                        }
                        Err(e) => {
                            total_blocks_rejected += 1;
                            let err_msg = e.to_string().to_lowercase();
                            // "already exists" is normal during sync — don't penalize
                            // Difficulty/stale-template rejects are often transient races
                            // between peers mining on nearby tips; treat as non-malicious.
                            if !is_non_penalized_block_rejection(&err_msg) {
                                // Ban feedback: penalize peer that sent the bad block
                                report_bad_peer_cat(
                                    peer_id,
                                    BAN_SCORE_INVALID_BLOCK,
                                    "invalid block rejected by consensus",
                                    BanCategory::Malformed,
                                );
                                slog_error!("daemon", "block_rejected_consensus", hash => hash_prefix, peer => peer_id, error => err_msg);
                            } else {
                                slog_warn!("daemon", "block_rejected_transient", hash => hash_prefix, peer => peer_id, error => err_msg);
                            }

                            // Chain sync: an orphan means we are missing this
                            // block's parent(s). Ask the sending peer for each
                            // missing ancestor and buffer the orphan so it is
                            // reprocessed once they arrive — for any orphan within
                            // the reorg window of our tip.
                            //
                            // NOT just strictly ABOVE our tip: when we are stuck
                            // on a side-branch tip, the canonical sibling we must
                            // download sits at the SAME height, so a strict `>`
                            // gate blocked its parent request — we would fetch the
                            // sibling, fail to place it (its own parent still
                            // missing), and drop it, looping forever without ever
                            // healing the fork (a lagging node never converged).
                            // FINALITY_DEPTH is exactly the set of competing
                            // chains that could out-weigh us; ancient orphans
                            // (below finality) still can't reorg us and stay
                            // ignored, so anti-thrash is preserved for old forks.
                            if err_msg.contains(ERR_ORPHAN) {
                                let best_h = self
                                    .block_store
                                    .get_best_hash()
                                    .and_then(|h| self.block_store.get_block_height(&h))
                                    .unwrap_or(0);
                                if orphan_worth_resolving(block.header.height, best_h) {
                                    for parent in &block.header.parents {
                                        if !parent.is_empty()
                                            && self.block_store.get_block(parent).is_none()
                                            && requested_parents.insert(parent.clone())
                                        {
                                            // Broadcast, not just to the relaying
                                            // peer: during multi-peer gossip the
                                            // relayer is often a fellow lagging node
                                            // that lacks the ancestor, while an
                                            // up-to-date peer has it. A peer without
                                            // the block ignores the request (block
                                            // serving is a store lookup that no-ops
                                            // on miss), so this reliably reaches
                                            // whoever can heal the fork.
                                            push_outbound(P2PMessage::GetBlock {
                                                hash: parent.clone(),
                                            });
                                        }
                                    }
                                    buffer_orphan(peer_id, block.clone());
                                }
                            }
                        }
                    }

                    processed_count += 1;
                    // Each block apply is fsync-bound (~0.5s: several RocksDB
                    // stores commit synchronously), so a 500ms budget clears just
                    // ONE block per tick — the follower IBD ceiling. During
                    // catch-up there are no user TXs to yield for, so give a much
                    // larger budget to drain a long contiguous run per tick, still
                    // bounded well under the pong timeout so keepalive/serving are
                    // unaffected.
                    let yield_budget = if was_catching_up {
                        std::time::Duration::from_secs(4)
                    } else {
                        std::time::Duration::from_millis(500)
                    };
                    if batch_start.elapsed() > yield_budget {
                        break;
                    }
                }
                // Re-queue any unprocessed blocks so they are not lost on timeout
                if processed_count < blocks.len() {
                    let remaining: Vec<_> = blocks.into_iter().skip(processed_count).collect();
                    requeue_pending_blocks(remaining);
                }

                // DURABLE COMMIT BOUNDARY: fsync the WAL once per accepted batch.
                // Sub-writes (block/UTXO/GHOSTDAG on the shared DB) use async WAL
                // for throughput; without a periodic sync an OS/power crash could
                // drop just-accepted blocks. One amortized fsync per batch makes
                // accepted state durable without an fsync per write. Recovery
                // rebuilds any un-synced tail from peers, and TolerateCorrupted-
                // TailRecords keeps the node bootable regardless. Contract state
                // lives in a separate DB (flushed by its own path when used).
                if accepted_this_batch {
                    if let Err(e) = self.db.flush_wal(true) {
                        slog_warn!("daemon", "wal_flush_failed", error => &e.to_string());
                    }
                }
                if far_future_dropped > 0 {
                    slog_debug!("daemon", "far_future_gossip_dropped",
                        count => &far_future_dropped.to_string(),
                        tip => &batch_best_height.to_string());
                }
            }

            // ── Serve block-download requests from peers (chain sync) ──
            // A peer that hit an orphan asks us for the missing ancestor; reply
            // with the block from our store so it can walk the chain forward and
            // converge. Without this, GetBlock is a no-op and forks never heal.
            // Paced, budgeted and round-robin for the same reasons as the
            // header path below: the per-pass budget is only a per-second bound
            // if the passes themselves are paced, and arrival order lets one
            // flooder be served first with everything it queued.
            let block_reqs = if block_pass_due(last_block_serve.elapsed()) {
                last_block_serve = Instant::now();
                drain_block_requests()
            } else {
                Vec::new()
            };
            if !block_reqs.is_empty() {
                did_work = true;
                let order = round_robin_by_peer(
                    &block_reqs
                        .iter()
                        .map(|(peer, _)| extract_ban_ip(peer))
                        .collect::<Vec<_>>(),
                    block_rr_cursor,
                );
                let mut bytes_total = 0usize;
                let mut processed = 0usize;
                // `served` is the enumerate index, so every request counts —
                // including one for a hash we do not have, which still costs a
                // point lookup.
                let mut deferred: Vec<(String, String)> = Vec::new();
                for (served, i) in order.into_iter().enumerate() {
                    if block_budget_spent(served, bytes_total) {
                        // Deferred, not dropped: the requester has no retry for
                        // an unanswered GetBlock, so dropping here would make
                        // the budget a hard ceiling on sync throughput instead
                        // of a rate. An ordinary event while catching up, hence
                        // debug rather than warn.
                        slog_debug!("daemon", "block_serve_budget_spent",
                            queued => block_reqs.len(),
                            requests_served => served,
                            bytes => bytes_total,
                            deferred => block_reqs.len().saturating_sub(served));
                        deferred.push(block_reqs[i].clone());
                        continue;
                    }
                    let (req_peer, hash) = &block_reqs[i];
                    if let Some(b) = self.block_store.get_block(hash) {
                        if let Ok(bytes) = bincode::serialize(&b) {
                            bytes_total = bytes_total.saturating_add(bytes.len());
                            push_outbound_to_peer(req_peer, P2PMessage::Block { data: bytes });
                        }
                    }
                    processed = served + 1;
                }
                // Move the lead on by what we got through, so the hosts this
                // pass could not reach lead the next one.
                block_rr_cursor = block_rr_cursor.wrapping_add(processed.max(1));
                requeue_block_requests(deferred);
            }

            // ── Serve header requests: walk the chain FORWARD from from_hash ──
            // and reply with a batch of hashes so a behind/forked peer can bulk-
            // download and catch up (far faster than the sequential orphan-walk).
            // Rate-bounded: the per-pass budget below only limits work per
            // second if the passes themselves are paced (did_work suppresses
            // the loop's only sleep while requests keep arriving).
            let header_reqs = if header_pass_due(last_header_serve.elapsed()) {
                last_header_serve = Instant::now();
                drain_header_requests()
            } else {
                Vec::new()
            };
            if !header_reqs.is_empty() {
                did_work = true;
                let order = round_robin_by_peer(
                    &header_reqs
                        .iter()
                        .map(|(peer, _, _)| extract_ban_ip(peer))
                        .collect::<Vec<_>>(),
                    header_rr_cursor,
                );
                let mut walked_total = 0usize;
                let mut hashes_total = 0usize;
                let mut processed = 0usize;
                // `served` is the enumerate index, so at the break it is exactly
                // the number of requests this pass processed.
                for (served, i) in order.into_iter().enumerate() {
                    if header_budget_spent(served, walked_total, hashes_total) {
                        slog_warn!("daemon", "header_serve_budget_spent",
                            queued => header_reqs.len(),
                            requests_served => served,
                            heights => walked_total,
                            hashes => hashes_total,
                            dropped => header_reqs.len().saturating_sub(served));
                        break;
                    }
                    let (req_peer, from_hash, count) = &header_reqs[i];
                    // Height from the h2h index, NOT get_block_height: that one
                    // tries the full block first, which is a read plus a bincode
                    // deserialize of up to MAX_BLOCK_SIZE on a path a remote peer
                    // triggers. Fall back only when the index has no entry, where
                    // the block read is a miss anyway.
                    let from_height = self
                        .block_store
                        .get_block_height_from_index(from_hash)
                        .or_else(|| self.block_store.get_block_height(from_hash));
                    // Walk forward from the requester's tip, INCLUDING same-height
                    // siblings, so a forked peer receives the canonical sibling it
                    // must adopt to heal (see collect_forward_headers).
                    let mut walked = 0usize;
                    let hashes = collect_forward_headers(from_hash, from_height, *count, |h| {
                        walked += 1;
                        self.block_store.get_block_hashes_at_height(h)
                    });
                    walked_total += walked;
                    hashes_total += hashes.len();
                    slog_info!("daemon", "header_serve",
                        to => req_peer.as_str(),
                        from => from_hash.get(..16).unwrap_or(from_hash.as_str()),
                        from_height => &from_height.map(|h| h.to_string()).unwrap_or_else(|| "none".into()),
                        served => hashes.len());
                    if !hashes.is_empty() {
                        push_outbound_to_peer(req_peer, P2PMessage::Headers { hashes });
                    }
                    processed = served + 1;
                }
                // Move the lead on by what we got through, so the hosts this
                // pass could not reach lead the next one.
                header_rr_cursor = header_rr_cursor.wrapping_add(processed.max(1));
            }

            // ── Drain pending transactions (peer-tagged) ────────────
            let mut txs = drain_pending_txs();
            let excess_txs = if txs.len() > TX_BATCH_LIMIT {
                txs.split_off(TX_BATCH_LIMIT)
            } else {
                Vec::new()
            };
            if !excess_txs.is_empty() {
                requeue_pending_txs(excess_txs);
            }
            if !txs.is_empty() {
                did_work = true;
                {
                    let mut mempool = self.mempool.lock();
                    let mut seen_tx_hashes: std::collections::HashSet<String> =
                        std::collections::HashSet::with_capacity(txs.len());
                    for (peer_id, tx) in txs.into_iter() {
                        // Skip duplicate TX hashes within the same drained batch.
                        // During relay races multiple peers can submit the same TX
                        // in the same tick; processing once is enough.
                        if !seen_tx_hashes.insert(tx.hash.clone()) {
                            continue;
                        }
                        // ── TX size check (defense-in-depth) ────────
                        // Reject oversized transactions before expensive
                        // validation. Uses the canonical serialization
                        // length against the DoS guard constant.
                        let tx_size = tx.canonical_bytes().len();
                        if tx_size > MAX_TX_BYTES {
                            total_txs_rejected += 1;
                            report_bad_peer_cat(
                                &peer_id,
                                BAN_SCORE_INVALID_TX,
                                &format!("TX_TOO_LARGE: {} > {}", tx_size, MAX_TX_BYTES),
                                BanCategory::Malformed,
                            );
                            continue;
                        }

                        // ── DagShield safety net (defense-in-depth) ──
                        if let Err(rej) = DagShield::pre_validate_tx(&tx) {
                            total_txs_rejected += 1;
                            report_bad_peer(&peer_id, rej.ban_score as u64, rej.reason);
                            continue;
                        }
                        let result = mempool.add_transaction(tx);
                        match result {
                            TxPoolResult::Accepted => {
                                total_txs_processed += 1;
                            }
                            // Duplicate, Orphan, DoubleSpend are non-malicious:
                            // these occur normally during sync and relay races.
                            // Do NOT increase ban score for these.
                            TxPoolResult::Duplicate | TxPoolResult::Orphan => {
                                total_txs_rejected += 1;
                            }
                            TxPoolResult::DoubleSpend => {
                                total_txs_rejected += 1;
                                // DoubleSpend may indicate misbehaviour but is
                                // common during reorgs — use a low score (1) so
                                // that sporadic duplicates don't trigger a ban.
                                report_bad_peer_cat(
                                    &peer_id,
                                    1,
                                    "double-spend tx",
                                    BanCategory::Resource,
                                );
                            }
                            // Invalid and Rejected are truly malformed/policy-violating.
                            TxPoolResult::Invalid | TxPoolResult::Rejected => {
                                total_txs_rejected += 1;
                                report_bad_peer_cat(
                                    &peer_id,
                                    BAN_SCORE_INVALID_TX,
                                    "invalid tx rejected by mempool",
                                    BanCategory::Malformed,
                                );
                            }
                        }
                    }
                }
            }

            // ── Drain discovered peer addresses into PeerManager ────
            // The P2P layer collects Addr messages from peers into
            // RECEIVED_ADDRS but doesn't add them to PeerManager.
            // Without this drain, dynamic peer discovery is dead.
            {
                use crate::service::network::p2p::p2p::drain_received_addrs;
                let addrs = drain_received_addrs();
                if !addrs.is_empty() {
                    // Persist discovered peers into the daemon's active peer manager.
                    // Using a temporary manager here drops discoveries on the floor.
                    for addr in &addrs {
                        let _ = self.peer_manager.add_peer(addr);
                    }
                    slog_info!("daemon", "peer_addrs_ingested", count => addrs.len());
                }
            }

            // ── Periodic stats ──────────────────────────────────────
            if last_stats.elapsed() >= STATS_INTERVAL {
                slog_info!("daemon", "event_loop_stats",
                    blocks_accepted => total_blocks_processed,
                    blocks_rejected => total_blocks_rejected,
                    txs_accepted => total_txs_processed,
                    txs_rejected => total_txs_rejected,
                    mempool_size => self.mempool.lock().tx_pool.mempool.count()
                );
                last_stats = Instant::now();
            }

            // ── Periodic durability checkpoint ──────────────────────
            // Flush memtables to SST + fsync the WAL every FLUSH_INTERVAL so an
            // unclean stop (SIGKILL / lost WAL across a container recreate)
            // cannot leave the shared store effectively empty and force a full
            // replay. Bounds worst-case loss to one flush window.
            if last_flush.elapsed() >= FLUSH_INTERVAL {
                self.flush_persist();
                last_flush = Instant::now();
            }

            // ── Adaptive sleep ──────────────────────────────────────
            // If we did work, poll again immediately (more data may be waiting).
            // If idle, sleep briefly to avoid busy-waiting.
            if !did_work {
                std::thread::sleep(POLL_INTERVAL);
            }
        }

        // ── Graceful shutdown ──────────────────────────────────────
        slog_info!("daemon", "shutting_down");
        slog_info!("daemon", "final_stats",
            blocks_accepted => total_blocks_processed,
            blocks_rejected => total_blocks_rejected,
            txs_accepted => total_txs_processed,
            txs_rejected => total_txs_rejected
        );

        self.flush_persist();
        slog_info!("daemon", "shutdown_complete");
    }

    /// Durably persist the shared DB: flush memtables to SST, then fsync the WAL.
    /// Called periodically during the event loop and once on graceful shutdown so
    /// an unclean stop cannot leave the store effectively empty.
    pub fn flush_persist(&self) {
        if let Err(e) = self.db.flush() {
            slog_warn!("daemon", "rocksdb_flush_failed", error => e);
        }
        if let Err(e) = self.db.flush_wal(true) {
            slog_warn!("daemon", "rocksdb_wal_flush_failed", error => e);
        }
    }

    // ── Public API ───────────────────────────────────────────────

    /// Process a new block through the FULL consensus pipeline.
    /// This is the ONLY way to add blocks — never bypass this.
    pub fn process_block(
        &self,
        block: &crate::domain::block::block::Block,
    ) -> Result<(), NodeError> {
        self.full_node.process_block(block)
    }

    /// Get the unified block processing engine
    pub fn full_node(&self) -> Arc<FullNode> {
        Arc::clone(&self.full_node)
    }

    pub fn dag(&self) -> Arc<DagManager> {
        Arc::clone(&self.dag)
    }

    pub fn block_store(&self) -> Arc<BlockStore> {
        Arc::clone(&self.block_store)
    }

    pub fn mempool(&self) -> Arc<Mutex<MempoolManager>> {
        Arc::clone(&self.mempool)
    }

    pub fn network(&self) -> &NetworkMode {
        &self.cfg.network
    }

    pub fn utxo_index(&self) -> Arc<Mutex<UtxoIndex>> {
        Arc::clone(&self.utxo_index)
    }

    pub fn tx_index(&self) -> Arc<Mutex<TxIndex>> {
        Arc::clone(&self.tx_index)
    }

    pub fn stratum_server(&self) -> &Option<Arc<StratumServer>> {
        &self.stratum_server
    }

    /// Build a VALID Stratum block template (real coinbase + merkle root) to
    /// push to pool miners. Returns None if no payout address is configured
    /// (`--stratum-address`), in which case the pool cannot produce a payable
    /// block. Coinbase-only for now (reward = emission; the pool distributes to
    /// workers off-chain) — including mempool txs in pool blocks is a follow-up.
    ///
    /// Uses the same tips/difficulty source (`get_dag_tips`/`get_next_difficulty`)
    /// the node keeps in lockstep with `mining_state`, so the template agrees
    /// with what `submitblock` expects.
    fn build_stratum_template(
        &self,
        accepted: &crate::domain::block::block::Block,
        job_id: String,
    ) -> Option<BlockTemplate> {
        use crate::config::consensus::consensus_params::ConsensusParams;
        use crate::config::consensus::emission_schedule::EmissionSchedule;
        use crate::config::node::node_config::NetworkMode;
        use crate::domain::block::merkle_tree::MerkleTree;
        use crate::domain::transaction::tx_builder::build_coinbase_at_height;
        use crate::service::network::nodes::full_node::{get_dag_tips, get_next_difficulty};

        let pool_addr = self.cfg.stratum_address.clone()?;

        // Parents = current DAG tips (fall back to the just-accepted block).
        let mut parents: Vec<String> =
            get_dag_tips().into_iter().filter(|h| !h.is_empty()).collect();
        if parents.is_empty() {
            parents.push(accepted.header.hash.clone());
        }
        parents.sort();
        parents.dedup();
        parents.truncate(ConsensusParams::MAX_PARENTS);

        // Height = max(parent heights) + 1 (== best_height + 1).
        let height = parents
            .iter()
            .filter_map(|h| self.block_store.get_block(h))
            .map(|b| b.header.height)
            .max()
            .unwrap_or(accepted.header.height)
            .saturating_add(1);

        let difficulty = get_next_difficulty().max(1);

        // Timestamp: strictly greater than every parent (R4), at least now.
        // Unix epoch MILLISECONDS; the +1 is now +1 ms (the ms granularity that
        // lets the selected chain advance faster than one block per wall-second).
        let max_parent_ts = parents
            .iter()
            .filter_map(|h| self.block_store.get_block(h))
            .map(|b| b.header.timestamp)
            .max()
            .unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let timestamp = now.max(max_parent_ts.saturating_add(1));

        let dev_addr = match self.cfg.network {
            NetworkMode::Mainnet => ConsensusParams::OWNER_REWARD_ADDRESS,
            NetworkMode::Testnet => crate::config::genesis::genesis::TESTNET_DEV_ADDRESS,
            NetworkMode::Regtest => crate::config::genesis::genesis::REGTEST_DEV_ADDRESS,
        }
        .to_string();
        let emission = EmissionSchedule::block_reward(height);
        let coinbase = build_coinbase_at_height(
            pool_addr,
            dev_addr,
            emission,
            ConsensusParams::MINER_PERCENT,
            timestamp,
            height,
        );
        let merkle_root = MerkleTree::build(std::slice::from_ref(&coinbase), height, &parents);

        Some(BlockTemplate {
            job_id,
            // ShadowHash (v2) template. Only reached on NON-fork networks: the
            // pool is disabled at construction where umbra_activation_height is
            // Some (see the FORK GUARD in Daemon::new). A future UmbraHash Stratum
            // path MUST network-gate this to UMBRA_POW_VERSION *and* hash UmbraHash.
            version: 2, // ms-timestamp era (matches GENESIS_VERSION)
            prev_hash: accepted.header.hash.clone(),
            parents,
            merkle_root,
            timestamp,
            difficulty,
            height,
            extra_nonce: 0,
            clean_jobs: true,
            transactions: vec![coinbase],
        })
    }

    // ── Crash Recovery ─────────────────────────────────────────

    /// Verify subsystems are roughly consistent after a restart.
    /// 3-level crash recovery:
    ///   A) BlockStore integrity — best hash + block must exist
    ///   B) DAG consistency — rebuild from BlockStore if DAG missing best block
    ///   C) UTXO integrity — compute_expected_utxo_count() vs actual count
    ///      - Empty UTXO (count=0) → full replay
    ///      - Partial mismatch (diff > 1% tolerance) → clear + full replay
    ///      - Within tolerance → continue normally
    fn verify_and_recover(&self) -> Result<(), NodeError> {
        // Step A: Check BlockStore integrity
        // Use get_best_hash_strict() to distinguish "absent" from "corrupt/unreadable".
        // A corrupt read here must be fatal — recovery with stale data is dangerous.
        let best_hash = self
            .block_store
            .get_best_hash_strict()
            .map_err(|e| {
                NodeError::Init(format!(
                    "FATAL: best_hash read failed during recovery (corrupt DB?): {}",
                    e
                ))
            })?
            .ok_or(NodeError::Init("No best hash found".to_string()))?;
        let best_block = self
            .block_store
            .get_block(&best_hash)
            .ok_or(NodeError::Init("Best block not found in store".to_string()))?;
        slog_info!("daemon", "recovery_blockstore_ok",
            best => &best_hash[..std::cmp::min(16, best_hash.len())],
            height => best_block.header.height);

        // Step B: Check DAG + GHOSTDAG consistency
        let dag_ok = self.dag.block_exists(&best_hash);
        let ghostdag_ok =
            self.ghostdag.get_blue_score(&best_hash) > 0 || best_block.header.height == 0;

        if !dag_ok || !ghostdag_ok {
            if !dag_ok {
                slog_warn!("daemon", "recovery_dag_missing_best_block");
            }
            if !ghostdag_ok {
                slog_warn!("daemon", "recovery_ghostdag_missing_scores");
            }
            self.rebuild_dag()?;
            self.rebuild_ghostdag()?;
        } else {
            slog_info!("daemon", "recovery_dag_ok");
            slog_info!("daemon", "recovery_ghostdag_ok", blue_score => self.ghostdag.get_blue_score(&best_hash));
        }

        // Step C: UTXO integrity — full content verification, not just count
        let utxo_count = self.utxo_set.count_utxos();
        if best_block.header.height > 0 && utxo_count == 0 {
            // Level 1: completely empty → full replay
            slog_warn!("daemon", "utxo_empty_replaying");
            self.replay_blocks()?;
        } else if best_block.header.height > 0 {
            // Level 2: UTXO integrity check on restart.
            //
            // PRIMARY: an EXACT cryptographic check via the rolling MuHash
            // accumulator. Unlike the per-block CHAINED commitment
            // (`utxo:commitment:{hash}`, a function of apply HISTORY and thus
            // incomparable to a set snapshot), the MuHash is a commitment to the
            // current unspent SET: recomputing it from the live set and comparing
            // to the value persisted atomically with the last apply detects
            // corruption or an apply/rollback bug exactly. Persisted per block, so
            // it is reorg-independent. FALLBACK: when no MuHash baseline exists
            // yet (first start after this landed, or legacy data), use the
            // reorg-independent ±1% count heuristic and then persist a baseline.
            let actual = utxo_count;
            match self.utxo_set.verify_muhash_integrity() {
                Some(true) => {
                    slog_info!("daemon", "utxo_ok_muhash", entries => actual);
                }
                Some(false) => {
                    slog_warn!("daemon", "utxo_muhash_mismatch_rebuilding", entries => actual);
                    self.utxo_set.clear_all();
                    self.replay_blocks()?;
                    slog_info!("daemon", "utxo_rebuilt", entries => self.utxo_set.count_utxos());
                }
                None => {
                    slog_info!("daemon", "utxo_count_integrity_check_no_muhash_baseline");
                    match self.compute_expected_utxo_count() {
                        Some(expected) => {
                            let tolerance = std::cmp::max(expected / 100, 10);
                            let diff = expected.abs_diff(actual);
                            if expected > 0 && diff > tolerance {
                                slog_warn!("daemon", "utxo_count_mismatch_rebuilding", expected => expected, actual => actual);
                                self.utxo_set.clear_all();
                                self.replay_blocks()?;
                                slog_info!("daemon", "utxo_rebuilt", entries => self.utxo_set.count_utxos());
                            } else {
                                // Count looks good and there was no baseline — persist
                                // one now so future restarts get the exact MuHash check.
                                self.utxo_set.rebuild_and_persist_muhash();
                                slog_info!("daemon", "utxo_ok_count_based_muhash_baseline_set", actual => actual, expected => expected);
                            }
                        }
                        None => {
                            // Selected-chain walk broken (corruption) — cannot compute a
                            // trustworthy expected count. Skip the heuristic rather than
                            // trigger a rebuild that would itself fail; leave the store
                            // as-is and let the operator decide to --reindex.
                            slog_warn!("daemon", "utxo_integrity_check_skipped_broken_selected_chain", actual => actual);
                        }
                    }
                }
            }
        } else {
            slog_info!("daemon", "utxo_ok", entries => utxo_count);
        }

        slog_info!("daemon", "recovery_all_subsystems_verified");
        Ok(())
    }

    /// Rebuild DAG topology from all blocks in BlockStore.
    ///
    /// LIMITATION: DagManager does not expose a clear_all() method, so stale
    /// entries from the previous state may persist.  add_block_validated()
    /// is idempotent for existing hashes, so the rebuild is still correct,
    /// but orphaned entries from a corrupted prior state will remain until
    /// a full re-index (--reindex) is performed.
    fn rebuild_dag(&self) -> Result<(), NodeError> {
        slog_warn!("daemon", "dag_rebuild_stale_entries_warning",
            message => "DagManager has no clear_all() — stale/orphaned entries from prior state will persist. \
                        Run with --reindex for a fully clean rebuild.");
        slog_info!("daemon", "dag_rebuild_start");
        let blocks = self.block_store.get_all_blocks_sorted_by_height();
        let total = blocks.len() as u64;
        let mut failed = 0u64;
        for block in &blocks {
            // Use validated=true since these blocks were already accepted
            if let Err(e) = self.dag.add_block_validated(block, true) {
                failed += 1;
                slog_warn!("daemon", "dag_rebuild_block_failed",
                    hash => block.header.hash,
                    height => block.header.height,
                    error => e
                );
            }
        }
        if failed > 0 {
            return Err(NodeError::Recovery(format!(
                "DAG rebuild had {} failures out of {} blocks — partial state is dangerous",
                failed, total
            )));
        }
        slog_info!("daemon", "dag_rebuilt", total => total, failed => failed);
        Ok(())
    }

    /// Rebuild GHOSTDAG ordering from all blocks in BlockStore.
    /// Must be called after rebuild_dag() to ensure consistent fork-choice state.
    fn rebuild_ghostdag(&self) -> Result<(), NodeError> {
        slog_info!("daemon", "ghostdag_rebuild_start");
        self.ghostdag.clear_all();

        let blocks = self.block_store.get_all_blocks_sorted_by_height();
        let total = blocks.len() as u64;
        let mut failed = 0u64;
        for block in &blocks {
            let dag_block = crate::engine::dag::ghostdag::ghostdag::DagBlock {
                hash: block.header.hash.clone(),
                parents: block.header.parents.clone(),
                height: block.header.height,
                timestamp: block.header.timestamp,
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.ghostdag.add_block(dag_block)
            }));
            match result {
                Err(e) => {
                    failed += 1;
                    let msg = e
                        .downcast_ref::<String>()
                        .map(|s| s.as_str())
                        .or_else(|| e.downcast_ref::<&str>().copied())
                        .unwrap_or("unknown panic");
                    slog_warn!("daemon", "ghostdag_rebuild_block_panicked",
                        hash => block.header.hash,
                        height => block.header.height,
                        error => msg
                    );
                }
                Ok(Err(e)) => {
                    failed += 1;
                    slog_warn!("daemon", "ghostdag_rebuild_block_failed",
                        hash => block.header.hash,
                        height => block.header.height,
                        error => e.to_string()
                    );
                }
                Ok(Ok(_)) => {}
            }
        }
        if failed > 0 {
            return Err(NodeError::Recovery(format!(
                "GHOSTDAG rebuild had {} failures out of {} blocks — partial state is dangerous",
                failed, total
            )));
        }

        // Re-derive best tip using the canonical GHOSTDAG selection rule.
        // Uses FullNode::select_best_tip_inner to guarantee runtime and recovery
        // always agree on fork-choice (cumulative work -> blue_score -> height
        // -> hash). A fresh local cache is fine — cumulative work is a pure
        // function of the chain, so it yields identical results to the runtime.
        let tips = self.ghostdag.get_tips();
        let mut cwork_cache = std::collections::HashMap::new();
        let best_tip = FullNode::select_best_tip_inner(
            &self.block_store,
            &self.ghostdag,
            &mut cwork_cache,
            &tips,
        );
        if let Some(ref best_tip) = best_tip {
            if !self.block_store.update_best_hash(best_tip) {
                slog_error!("daemon", "rebuild_ghostdag_best_hash_failed",
                    tip => crate::domain::types::hash::log_prefix(best_tip, 16));
                return Err(NodeError::Init(
                    "failed to persist best_hash after GHOSTDAG rebuild".into(),
                ));
            }
            slog_info!("daemon", "ghostdag_rebuilt",
                total => total,
                failed => failed,
                best_tip => &best_tip[..std::cmp::min(16, best_tip.len())],
                blue_score => self.ghostdag.get_blue_score(best_tip)
            );
        } else {
            slog_info!("daemon", "ghostdag_rebuilt_no_tips", total => total, failed => failed);
        }

        Ok(())
    }

    /// Replay the SELECTED (virtual) chain to rebuild UTXO state.
    ///
    /// Walks the selected-parent chain from the best tip back to genesis
    /// (recovery_blocks), then replays oldest→newest via
    /// apply_block_dag_ordered — the SAME set the live recompute_virtual_chain
    /// applies, so recovery reproduces the live UTXO state exactly.
    ///
    /// Replaying every stored block (the old behavior) also applied red /
    /// side-branch coinbases, minting UTXOs the canonical chain never created
    /// = inflation. The historical "utxo_replay_complete blocks=1" crash that
    /// pushed the old code to all-blocks was a DIFFERENT bug — stored
    /// selected_parent was None so the walk stopped after one hop; that is now
    /// fixed by BlockHeader::resolved_selected_parent (falls back to the first
    /// PoW-covered parent), so the selected-chain walk is safe again.
    fn replay_blocks(&self) -> Result<(), NodeError> {
        slog_info!("daemon", "utxo_replay_start");

        // Replay the SELECTED chain only (not every stored block) so red /
        // side-branch coinbases are never minted into the UTXO set — that
        // would create spendable coins beyond the canonical emission
        // (inflation). Matches the live recompute_virtual_chain apply set.
        // A broken walk (corruption) is fatal — refuse to rebuild an incorrect
        // ledger; the operator must --reindex.
        let blocks = self.recovery_blocks().ok_or_else(|| {
            NodeError::Init(
                "cannot rebuild UTXO set: the selected-parent chain is broken (missing ancestor \
                 or cycle). Run with --reindex or delete the data directory to force a full rebuild."
                    .into(),
            )
        })?;

        if blocks.is_empty() {
            slog_info!("daemon", "utxo_replay_complete", blocks => 0);
            return Ok(());
        }

        for block in &blocks {
            self.utxo_set
                .apply_block_dag_ordered(
                    &block.body.transactions,
                    block.header.height,
                    &block.header.hash,
                )
                .map_err(|e| {
                    NodeError::Init(format!(
                        "replay failed at height {} hash {}: {}",
                        block.header.height, block.header.hash, e
                    ))
                })?;
        }

        slog_info!("daemon", "utxo_replay_complete", blocks => blocks.len());
        Ok(())
    }

    /// Walk the SELECTED (virtual) chain from `tip` back to genesis via each
    /// block's resolved selected parent, returning blocks oldest→newest.
    ///
    /// CONSENSUS-CRITICAL: recovery must reflect the SAME set of blocks the
    /// live apply path (recompute_virtual_chain) applies — the selected chain
    /// ONLY. Replaying every stored block (get_all_blocks_sorted_by_height)
    /// also applies RED / side-branch coinbases, minting UTXOs that the
    /// canonical chain never created → spendable coins beyond the per-height
    /// emission schedule (inflation past MAX_SUPPLY on any DAG with width).
    ///
    /// Returns None if the walk is broken (missing ancestor or a cycle) so the
    /// caller can fall back to the full block set rather than rebuild an
    /// INCOMPLETE UTXO state. Pure over `get_block` for unit testing.
    fn selected_chain_from(
        tip: Option<String>,
        get_block: impl Fn(&str) -> Option<crate::domain::block::block::Block>,
    ) -> Option<Vec<crate::domain::block::block::Block>> {
        let mut cursor = tip?;
        let mut chain: Vec<crate::domain::block::block::Block> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            if !seen.insert(cursor.clone()) {
                return None; // cycle — corrupt topology
            }
            let block = get_block(&cursor)?; // missing ancestor → broken walk
            let parent = block.header.resolved_selected_parent();
            chain.push(block);
            match parent {
                Some(p) if !p.is_empty() => cursor = p,
                _ => break, // reached genesis
            }
        }
        chain.reverse(); // oldest → newest (GHOSTDAG apply order)
        Some(chain)
    }

    /// The blocks recovery should replay/count: the SELECTED chain, walked
    /// from the best tip back to genesis.
    ///
    /// Returns None when the walk is broken (a missing ancestor or a cycle =
    /// block-store corruption). We deliberately do NOT fall back to the full
    /// stored set: that would replay every red / side-branch coinbase and mint
    /// UTXOs beyond the canonical emission (inflation), which is strictly worse
    /// than refusing to proceed. Callers surface the corruption and ask the
    /// operator to --reindex. DAG + GHOSTDAG are rebuilt earlier in recovery
    /// (Step B), so an intact store always yields a complete walk here.
    fn recovery_blocks(&self) -> Option<Vec<crate::domain::block::block::Block>> {
        // Use the PERSISTED best_hash — the exact tip the live path selected
        // and applied. The live recompute_virtual_chain uses
        // should_keep_current_tip_on_tie, which on a 3-way (cumulative_work,
        // blue_score, chain_height) tie KEEPS the current tip regardless of
        // hash, then persists it. Recomputing here via select_best_tip (whose
        // tiebreak is lower-hash, with no current-tip context) could pick the
        // OTHER sibling, so the rebuilt UTXO set would reflect a different
        // chain than the stored best_hash → post-recovery ledger/tip divergence
        // (a consensus-split risk on any width>1 DAG with a genuine tie).
        // Fall back to select_best_tip only when nothing is persisted yet.
        let tip = self.block_store.get_best_hash().or_else(|| {
            let tips = self.ghostdag.get_tips();
            self.full_node.select_best_tip(&tips)
        });
        Self::selected_chain_from(tip, |h| self.block_store.get_block(h))
    }

    /// Compute expected UTXO count by walking the SELECTED chain (matching the
    /// live UTXO state). For each block: outputs created - inputs spent = net
    /// change. Sum all net changes = expected unspent UTXO count. None when the
    /// selected chain can't be walked (corruption) — the caller then SKIPS the
    /// count check rather than triggering a rebuild that would also fail.
    fn compute_expected_utxo_count(&self) -> Option<usize> {
        let blocks = self.recovery_blocks()?;
        let mut total_created: usize = 0;
        let mut total_spent: usize = 0;

        for block in &blocks {
            for tx in &block.body.transactions {
                total_created += tx.outputs.len();
                // Validate that coinbase flag matches actual structure:
                // a real coinbase must have 0 inputs. If the flag is set
                // but inputs exist, treat it as a regular TX to avoid
                // undercounting spent UTXOs.
                let is_real_coinbase = tx.is_coinbase() && tx.inputs.is_empty();
                if !is_real_coinbase {
                    total_spent += tx.inputs.len();
                }
            }
        }

        Some(total_created.saturating_sub(total_spent))
    }

    fn print_banner(&self) {
        slog_info!("daemon", "banner",
            network => self.cfg.network.name(),
            data_dir => self.cfg.data_dir.display(),
            p2p_port => self.cfg.p2p_port,
            rpc_port => self.cfg.rpc_port
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a DaemonNode with a unique temp data directory to avoid
    /// RocksDB file locking conflicts when tests run in parallel.
    fn daemon_with_temp_dir(network: NetworkMode) -> DaemonNode {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut cfg = NodeConfig::for_network(network);
        cfg.data_dir = std::path::PathBuf::from(format!(
            "{}/shadowdag_test_{}_{}",
            std::env::temp_dir().display(),
            cfg.network.short_name(),
            ts
        ));
        DaemonNode::new(cfg).expect(
            "failed to create DaemonNode for test — check NodeConfig and data_dir permissions",
        )
    }

    #[test]
    fn daemon_testnet_has_correct_ports() {
        let d = daemon_with_temp_dir(NetworkMode::Testnet);
        assert_eq!(d.cfg.p2p_port, 19333);
        assert_eq!(d.cfg.rpc_port, 19332);
    }

    #[test]
    fn daemon_regtest_has_correct_ports() {
        let d = daemon_with_temp_dir(NetworkMode::Regtest);
        assert_eq!(d.cfg.p2p_port, 29333);
    }

    #[test]
    fn daemon_mainnet_is_default() {
        let d = daemon_with_temp_dir(NetworkMode::Mainnet);
        assert!(d.cfg.network.is_mainnet());
    }

    /// Build a DaemonNode with `enable_stratum = true` on the given network.
    fn daemon_with_stratum(network: NetworkMode) -> DaemonNode {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut cfg = NodeConfig::for_network(network);
        cfg.enable_stratum = true;
        cfg.data_dir = std::path::PathBuf::from(format!(
            "{}/shadowdag_test_stratum_{}_{}",
            std::env::temp_dir().display(),
            cfg.network.short_name(),
            ts
        ));
        DaemonNode::new(cfg).expect("failed to create DaemonNode for stratum test")
    }

    #[test]
    fn stratum_disabled_on_all_networks_under_m5() {
        // FORK/M5 GUARD: the ShadowHash-only, pre-M5 Stratum pool stamps
        // prev_state_commitment = None, which the M5 deferred-state-commitment
        // verify rejects for every height>0 block on EVERY network (in addition to
        // the UmbraHash floor rejecting its v2 blocks on mainnet). The daemon must
        // therefore refuse to start the dead pool regardless of network.
        for network in [NetworkMode::Mainnet, NetworkMode::Testnet, NetworkMode::Regtest] {
            let d = daemon_with_stratum(network.clone());
            assert!(
                d.stratum_server().is_none(),
                "Stratum pool must be disabled under M5 on {:?} (pool stamps a None commitment the verify rejects)",
                network
            );
        }
    }

    #[test]
    fn fresh_chain_genesis_publishes_height1_commitment() {
        // M5 FRESH-CHAIN HALT REGRESSION. On a brand-new chain the daemon accepts
        // genesis via FullNode::process_genesis and does NOT call
        // recompute_virtual_chain (that only runs on the existing-chain restart
        // branch). process_genesis MUST publish the mining template over the real
        // tips ([genesis]) so the height-1 getblocktemplate serves
        // compute_prev_state_commitment(genesis_hash) — the exact value the
        // validator recomputes for parents=[genesis]. Before the fix, the published
        // cell kept the empty-parent genesis commitment seeded in FullNode::new
        // (store empty at construction), so every height-1 block was rejected on a
        // mismatch => the chain deadlocked at genesis on every fresh bring-up. This
        // asserts the per-instance cell (non-racy) directly.
        use crate::engine::mining::algorithms::shadowhash::{
            compute_prev_state_commitment, genesis_prev_state_commitment,
        };
        use crate::service::network::nodes::full_node::expected_prev_state_commitment;

        let d = daemon_with_temp_dir(NetworkMode::Regtest);
        let fnode = d.full_node();

        // At construction the store is empty, so the seed is the empty-parent value
        // — which is WRONG for a height-1 block whose selected parent is genesis.
        let empty_parent = genesis_prev_state_commitment();
        assert_eq!(
            fnode.mining_state.prev_state_commitment(),
            Some(empty_parent.clone()),
            "pre-genesis seed should be the empty-parent genesis commitment"
        );

        let genesis = create_genesis_block_for(&NetworkMode::Regtest);
        fnode
            .process_genesis(&genesis)
            .expect("genesis processing must succeed");

        let published = fnode.mining_state.prev_state_commitment();
        let expected = expected_prev_state_commitment(
            std::slice::from_ref(&genesis.header.hash),
            &fnode.ghostdag,
            &fnode.block_store,
        );
        let height1 = compute_prev_state_commitment(&genesis.header.hash, None, None, None);

        assert_eq!(
            published,
            Some(expected),
            "process_genesis must publish the commitment the validator recomputes for parents=[genesis]"
        );
        assert_eq!(
            published,
            Some(height1),
            "published commitment must bind the genesis-hash selected parent (the height-1 value)"
        );
        assert_ne!(
            published,
            Some(empty_parent),
            "published commitment must NOT remain the empty-parent genesis value (that halts height 1)"
        );
    }

    #[test]
    fn republish_mining_template_corrects_stale_seed() {
        // M5 RESTART HALT REGRESSION. FullNode::new seeds the mining cells from the
        // DAG at construction (BEFORE verify_and_recover may rebuild a corrupt DAG),
        // and recompute_virtual_chain early-returns without republishing when the
        // recomputed best equals the persisted best (the normal restart case). Under
        // M5 a stale commitment makes getblocktemplate serve a value the height>=1
        // validator rejects => block-production halt on that node.
        // republish_mining_template (called by daemon start() after recovery) MUST
        // overwrite any stale value with the commitment derived from the CURRENT
        // tips. Simulate the stale construction seed by poisoning the cell, then
        // assert republish restores the correct height-1 value. Non-racy
        // (per-instance cell).
        use crate::engine::mining::algorithms::shadowhash::compute_prev_state_commitment;

        let d = daemon_with_temp_dir(NetworkMode::Regtest);
        let fnode = d.full_node();
        let genesis = create_genesis_block_for(&NetworkMode::Regtest);
        fnode.process_genesis(&genesis).expect("genesis must succeed");

        let correct = compute_prev_state_commitment(&genesis.header.hash, None, None, None);

        // Poison the per-instance cell with a wrong (but valid-shaped) value, as a
        // stale construction seed from a pre-rebuild DAG would leave it.
        fnode
            .mining_state
            .set_prev_state_commitment(Some("00".repeat(32)));
        assert_ne!(
            fnode.mining_state.prev_state_commitment(),
            Some(correct.clone()),
            "precondition: the cell is poisoned with a stale value"
        );

        fnode.republish_mining_template();

        assert_eq!(
            fnode.mining_state.prev_state_commitment(),
            Some(correct),
            "republish must restore the commitment derived from the current tips ([genesis])"
        );
    }

    #[test]
    fn dag_arc_is_shared() {
        let d = daemon_with_temp_dir(NetworkMode::Mainnet);
        let a = d.dag();
        let b = d.dag();
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn full_node_is_accessible() {
        let d = daemon_with_temp_dir(NetworkMode::Mainnet);
        let fn1 = d.full_node();
        let fn2 = d.full_node();
        assert!(Arc::ptr_eq(&fn1, &fn2));
    }

    #[test]
    fn orphan_resolution_covers_same_height_and_reorg_window() {
        // A competing chain at the SAME height as our tip MUST be resolved —
        // this is the fix for a node stuck forever on a side-branch tip (its
        // canonical sibling is at the same height, which the old strict `>` gate
        // refused to fetch). Also resolve strictly-above and within the finality
        // window below; ignore ancient orphans (anti-thrash).
        assert!(
            orphan_worth_resolving(1659, 1659),
            "same-height competing chain must be resolved (side-branch convergence)"
        );
        assert!(orphan_worth_resolving(1660, 1659), "above-tip orphan resolved");
        assert!(
            orphan_worth_resolving(1659 - 199, 1659),
            "within the finality window must be resolved"
        );
        assert!(
            !orphan_worth_resolving(1659u64.saturating_sub(500), 1659),
            "ancient orphan (below finality) ignored — anti-thrash"
        );
        // W2: a FAR-ahead orphan must NOT trigger a backward orphan-walk — it is
        // reached by forward header-sync. Resolving it floods a far-behind node
        // and it can't reorg us anyway.
        assert!(
            orphan_worth_resolving(1659 + 200, 1659),
            "an orphan exactly FINALITY_DEPTH above the tip is still a competitor"
        );
        assert!(
            !orphan_worth_resolving(1659 + 201, 1659),
            "an orphan beyond FINALITY_DEPTH above the tip is left for forward header-sync"
        );
        assert!(
            !orphan_worth_resolving(9 + 500, 9),
            "a fresh node must NOT orphan-walk far-ahead gossip (the flood cause)"
        );
    }

    #[test]
    fn far_future_gossip_gate_drops_flood_but_keeps_reorg_and_catchup() {
        use crate::engine::consensus::reorg::FINALITY_DEPTH;
        let tip = 9u64; // a far-behind node
        // The tall-chain flood (height ~10000) is dropped cheaply.
        assert!(is_far_future_gossip(10_000, tip), "far-future flood must be dropped");
        // The very next block and header-sync catch-up blocks are KEPT.
        assert!(!is_far_future_gossip(tip + 1, tip), "next block must be processed");
        assert!(!is_far_future_gossip(tip + 64, tip), "header-sync batch must be processed");
        // A genuine reorg competitor (within FINALITY_DEPTH of the tip) is KEPT.
        assert!(
            !is_far_future_gossip(tip + FINALITY_DEPTH, tip),
            "a reorg competitor within FINALITY_DEPTH must never be dropped"
        );
        // A caught-up node never sees far-future gossip: its next block is in-window.
        let caught_up = 10_000u64;
        assert!(!is_far_future_gossip(caught_up + 1, caught_up));
        // The boundary: exactly at the window edge is kept; one past is dropped.
        assert!(!is_far_future_gossip(tip + FAR_FUTURE_GOSSIP_WINDOW, tip));
        assert!(is_far_future_gossip(tip + FAR_FUTURE_GOSSIP_WINDOW + 1, tip));
    }

    #[test]
    fn header_serve_includes_canonical_sibling_at_tip_height() {
        // A node stuck on a side-branch tip must receive the CANONICAL sibling at
        // its OWN height to heal the fork. The walk starts AT from_hash's height,
        // returns the sibling, and skips from_hash itself.
        let from_hash = "aaaa"; // requester's side-branch tip at height 1659
        let sibling = "bbbb"; // canonical block at the SAME height
        let next = "cccc"; // canonical child at height 1660
        let at = |h: u64| -> Vec<String> {
            match h {
                1659 => vec![from_hash.to_string(), sibling.to_string()],
                1660 => vec![next.to_string()],
                _ => vec![],
            }
        };
        let out = collect_forward_headers(from_hash, Some(1659), 512, at);
        assert!(
            out.contains(&sibling.to_string()),
            "canonical sibling at the requester's own height must be served"
        );
        assert!(
            out.contains(&next.to_string()),
            "forward blocks past the tip must be served"
        );
        assert!(
            !out.contains(&from_hash.to_string()),
            "requester's own tip must be skipped"
        );
        // Ordering: the same-height sibling precedes the next-height child.
        let si = out.iter().position(|x| x == sibling).unwrap();
        let ni = out.iter().position(|x| x == next).unwrap();
        assert!(si < ni, "same-height sibling served before the next-height child");
    }

    #[test]
    fn header_serve_budget_is_spent_round_robin_not_in_arrival_order() {
        // A flooder's requests arrive first and fill the queue; two honest
        // peers are behind them. Round-robin must reach both honest peers
        // within the first few served slots, or the per-tick budget this
        // commit adds would starve them — the F12 failure class.
        let mut peers: Vec<&str> = (0..64).map(|_| "flooder").collect();
        peers.push("seed1");
        peers.push("seed2");

        let order = round_robin_by_peer(&peers, 0);
        assert_eq!(order.len(), peers.len(), "every request must be ordered");
        // A real permutation of 0..n: the serve loop indexes header_reqs[i]
        // with these, so a lost or repeated index would drop a request or
        // panic.
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            (0..peers.len()).collect::<Vec<_>>(),
            "the order must be a permutation of the request indices"
        );

        let first_three: Vec<&str> = order.iter().take(3).map(|i| peers[*i]).collect();
        assert!(
            first_three.contains(&"seed1") && first_three.contains(&"seed2"),
            "both honest peers must be served in the first round, got {:?}",
            first_three
        );
        // The flooder is not punished either: it keeps every request, just
        // behind one per round.
        assert_eq!(
            order.iter().filter(|i| peers[**i] == "flooder").count(),
            64
        );
        // Stable within a peer: a single peer's requests keep arrival order.
        let flooder_positions: Vec<usize> = order
            .iter()
            .copied()
            .filter(|i| peers[*i] == "flooder")
            .collect();
        assert!(
            flooder_positions.windows(2).all(|w| w[0] < w[1]),
            "a peer's own requests must stay in arrival order"
        );
    }

    #[test]
    fn the_block_serve_budget_counts_every_request_not_just_the_hits() {
        // The old counter advanced only when a block was FOUND and serialized,
        // so a flood of hashes we do not have was unbounded work per pass: each
        // one still costs a RocksDB point lookup.
        assert!(
            block_budget_spent(MAX_BLOCK_SERVES_PER_TICK, 0),
            "a pass that found nothing at all must still run out of budget"
        );
        assert!(!block_budget_spent(
            MAX_BLOCK_SERVES_PER_TICK - 1,
            MAX_BLOCK_SERVE_BYTES_PER_TICK - 1
        ));
        // The byte dimension binds on its own: a block runs to MAX_BLOCK_BYTES
        // and all of it lands in TARGETED_MSGS, which has no byte bound.
        assert!(block_budget_spent(1, MAX_BLOCK_SERVE_BYTES_PER_TICK));
        // And one maximum-size block must always get through, since the budget
        // is checked before a request is served.
        assert!(!block_budget_spent(0, 0));
        const { 
            assert!(
                MAX_BLOCK_SERVE_BYTES_PER_TICK
                    >= crate::service::network::dos_guard::MAX_BLOCK_BYTES,
                "one maximum block must fit in a pass byte budget"
            )
        };
    }

    #[test]
    fn the_block_serve_budget_is_a_rate_only_because_the_passes_are_paced() {
        // Same reasoning as the header path: without a pass interval the
        // per-pass numbers bound nothing per second, because did_work
        // suppresses the loop only sleep while requests keep arriving.
        assert!(block_pass_due(BLOCK_SERVE_INTERVAL));
        assert!(!block_pass_due(
            BLOCK_SERVE_INTERVAL - std::time::Duration::from_millis(1)
        ));
        let passes_per_sec = 1_000 / BLOCK_SERVE_INTERVAL.as_millis() as usize;
        assert_eq!(passes_per_sec * MAX_BLOCK_SERVES_PER_TICK, 5_120);
        assert_eq!(
            passes_per_sec * MAX_BLOCK_SERVE_BYTES_PER_TICK,
            40 * 1024 * 1024
        );
        // The request budget must sit ABOVE the honest per-host burst, the way
        // the header budget does. Below it, a normal sync round could never be
        // served in one pass — which is what made the remainder's fate matter
        // so much in the first place.
        const {
            assert!(
                MAX_BLOCK_SERVES_PER_TICK
                    >= crate::service::network::p2p::p2p::MAX_BLOCK_REQUESTS_PER_IP / 2,
                "a pass must be able to clear a substantial part of one burst"
            )
        };
    }

    #[test]
    fn the_header_serve_budget_binds_in_all_three_dimensions() {
        // Fresh tick: nothing is spent.
        assert!(!header_budget_spent(0, 0, 0));
        // Egress binds on its own: a DAG w blocks wide yields w hashes per
        // walked height, so heights alone never bounded reply bytes.
        assert!(header_budget_spent(1, 1, MAX_HEADER_HASHES_PER_TICK));
        // A flood of requests pointed past our tip returns nothing, so it must
        // be bounded by the SERVED count: each one still costs a store lookup
        // and a log line.
        assert!(header_budget_spent(MAX_HEADER_SERVES_PER_TICK, 1, 0));
        assert!(!header_budget_spent(
            MAX_HEADER_SERVES_PER_TICK - 1,
            MAX_HEADER_HEIGHTS_PER_TICK - 1,
            MAX_HEADER_HASHES_PER_TICK - 1
        ));
        // Many cheap replies spend it...
        assert!(header_budget_spent(MAX_HEADER_SERVES_PER_TICK, 0, 0));
        // ...and so does a little walking that costs a lot: eight
        // from-genesis walks of 512 heights, which is how the old loop could
        // reach ~1.02M prefix iterators in one pass.
        assert!(header_budget_spent(8, MAX_HEADER_HEIGHTS_PER_TICK, 0));
        assert!(header_budget_spent(0, MAX_HEADER_HEIGHTS_PER_TICK, 0));
        // The budget must leave honest sync untouched: one request per peer
        // per 6 s sync_interval across the whole peer set is nowhere near it.
        assert!(!header_budget_spent(
            crate::service::network::p2p::p2p::MAX_PEERS,
            512,
            512,
        ));
    }

    #[test]
    fn the_header_serve_rate_ceiling_is_what_the_doc_claims() {
        // A per-pass budget bounds nothing per second unless the passes are
        // paced. This is the arithmetic the constants' doc comment states, so
        // changing a constant without the doc fails here.
        assert!(header_pass_due(HEADER_SERVE_INTERVAL));
        assert!(!header_pass_due(
            HEADER_SERVE_INTERVAL - std::time::Duration::from_millis(1)
        ));
        assert!(!header_pass_due(std::time::Duration::ZERO));

        let passes_per_sec = 1_000 / HEADER_SERVE_INTERVAL.as_millis() as usize;
        assert_eq!(passes_per_sec, 20);
        assert_eq!(passes_per_sec * MAX_HEADER_SERVES_PER_TICK, 5_120);
        assert_eq!(passes_per_sec * MAX_HEADER_HEIGHTS_PER_TICK, 163_840);
        assert_eq!(passes_per_sec * MAX_HEADER_HASHES_PER_TICK, 163_840);

        // The honest worst case must fit well inside it: every one of
        // MAX_PEERS catching up at once asks twice a second (the fast-sync
        // interval) and each reply is a full 512-hash batch.
        let storm_requests = crate::service::network::p2p::p2p::MAX_PEERS * 2;
        let storm_hashes = storm_requests * 512;
        assert!(
            storm_requests < passes_per_sec * MAX_HEADER_SERVES_PER_TICK,
            "{} requests/s must fit the serve ceiling",
            storm_requests
        );
        assert!(
            storm_hashes * 2 < passes_per_sec * MAX_HEADER_HASHES_PER_TICK,
            "{} hashes/s leaves less than 2x headroom",
            storm_hashes
        );
        // Heights need the same check. They had 1.25x and nothing asserted it:
        // a walk on a width-1 chain visits one height per hash returned.
        let storm_heights = storm_hashes;
        assert!(
            storm_heights * 2 < passes_per_sec * MAX_HEADER_HEIGHTS_PER_TICK,
            "{} heights/s leaves less than 2x headroom",
            storm_heights
        );
    }

    #[test]
    fn header_serve_fairness_is_per_host_not_per_socket() {
        // The composition the serve loop uses. Keying the rounds on the raw
        // peer_id would hand one host MAX_PEERS_PER_IP first-round slots,
        // which is the same mistake the queue quota already avoids.
        let reqs = [
            "203.0.113.9:40001",
            "203.0.113.9:40002",
            "203.0.113.9:40003",
            "198.51.100.5:40004",
        ];
        let keys: Vec<String> = reqs.iter().map(|p| extract_ban_ip(p)).collect();
        let order = round_robin_by_peer(&keys, 0);

        // Round 0 is one slot per HOST, so it holds exactly two entries and
        // the honest host is one of them.
        let round0: Vec<&str> = order.iter().take(2).map(|i| keys[*i].as_str()).collect();
        assert!(
            round0.contains(&"198.51.100.5"),
            "the honest host must be in the first round, got {:?}",
            round0
        );
        assert_eq!(
            round0.iter().collect::<std::collections::HashSet<_>>().len(),
            2,
            "the first round must hold one slot per host"
        );
        // Keyed on the socket instead, all three of the busy host's requests
        // would precede the honest one.
        let by_socket = round_robin_by_peer(&reqs, 0);
        assert_eq!(
            by_socket.iter().take(3).map(|i| reqs[*i]).filter(|p| p.starts_with("203.0.113.9")).count(),
            3,
            "this is what keying on the socket would have done"
        );
    }

    #[test]
    fn rotating_the_lead_reaches_every_host_within_a_few_passes() {
        // The budget is SHARED, so ordering alone cannot stop eight expensive
        // requests from spending a whole pass. What must not happen is the same
        // hosts leading every pass: a flooder always has a request queued, so
        // without rotation it would lead forever and the hosts behind it would
        // never be served at all.
        let hosts: Vec<String> = (0..10).map(|i| format!("host{}", i)).collect();
        const SERVED_PER_PASS: usize = 3;

        let mut cursor = 0usize;
        let mut ever_served: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for _ in 0..4 {
            let order = round_robin_by_peer(&hosts, cursor);
            let served: Vec<&str> = order
                .iter()
                .take(SERVED_PER_PASS)
                .map(|i| hosts[*i].as_str())
                .collect();
            for h in &served {
                ever_served.insert(h);
            }
            cursor = cursor.wrapping_add(served.len());
        }
        assert_eq!(
            ever_served.len(),
            hosts.len(),
            "every host must be reached within ceil(hosts/served) passes, missed {:?}",
            hosts
                .iter()
                .filter(|h| !ever_served.contains(h.as_str()))
                .collect::<Vec<_>>()
        );

        // Without rotation the same three lead every pass, which is the
        // starvation this exists to prevent.
        let mut frozen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for _ in 0..4 {
            for i in round_robin_by_peer(&hosts, 0).iter().take(SERVED_PER_PASS) {
                frozen.insert(hosts[*i].as_str());
            }
        }
        assert_eq!(frozen.len(), SERVED_PER_PASS);
    }

    #[test]
    fn round_robin_handles_the_ordinary_shapes() {
        // Empty, single, and one-each are the common cases — no reordering.
        let empty: Vec<&str> = Vec::new();
        assert!(round_robin_by_peer(&empty, 0).is_empty());
        assert!(round_robin_by_peer(&empty, 7).is_empty());
        assert_eq!(round_robin_by_peer(&["a"], 0), vec![0]);
        // A cursor past the host count wraps, it does not panic.
        assert_eq!(round_robin_by_peer(&["a"], 99), vec![0]);
        assert_eq!(round_robin_by_peer(&["a", "b", "c"], 0), vec![0, 1, 2]);
        // Rotated: the second host leads.
        assert_eq!(round_robin_by_peer(&["a", "b", "c"], 1), vec![1, 2, 0]);
        // Interleaved: round 1 takes a,b then round 2 takes a's second.
        assert_eq!(round_robin_by_peer(&["a", "a", "b"], 0), vec![0, 2, 1]);
    }

    #[test]
    fn header_serve_walk_cost_is_counted_per_visited_height() {
        // The per-tick height budget is only sound if a walk's cost is really
        // the number of at_height calls. A from-genesis walk on a chain with
        // one block per height visits one height per returned hash.
        let mut walked = 0usize;
        let out = collect_forward_headers("unknown", None, 512, |h| {
            walked += 1;
            if h <= 10 {
                vec![format!("h{}", h)]
            } else {
                vec![]
            }
        });
        assert_eq!(out.len(), 10);
        assert_eq!(
            walked, 11,
            "ten populated heights plus the empty one that ends the walk"
        );

        // And a near-tip request is cheap — one height, which is why the
        // budget counts heights and not just replies.
        let mut walked_near = 0usize;
        let _ = collect_forward_headers("tip", Some(100), 512, |h| {
            walked_near += 1;
            if h == 100 {
                vec!["tip".to_string()]
            } else {
                vec![]
            }
        });
        assert_eq!(walked_near, 2, "the tip height, then the empty one");
    }

    #[test]
    fn header_serve_unknown_tip_starts_from_genesis() {
        // If we have never seen the requester's tip, serve from genesis so a
        // forked peer receives our whole chain.
        let at = |h: u64| -> Vec<String> {
            match h {
                1 => vec!["g1".to_string()],
                2 => vec!["g2".to_string()],
                _ => vec![],
            }
        };
        let out = collect_forward_headers("unknown", None, 512, at);
        assert_eq!(out, vec!["g1".to_string(), "g2".to_string()]);
    }

    #[test]
    fn header_serve_respects_count_cap() {
        // The reply is bounded by the requested count (itself clamped to 512).
        let at = |h: u64| -> Vec<String> {
            if h <= 1000 {
                vec![format!("h{}", h)]
            } else {
                vec![]
            }
        };
        let out = collect_forward_headers("x", Some(0), 10, at);
        assert_eq!(out.len(), 10, "must not exceed the requested count");
        assert_eq!(out[0], "h0", "walk begins at the requester's own height");
    }

    #[test]
    fn header_serve_no_sibling_walks_forward_normally() {
        // The common (non-forked) case: the requester's tip has no sibling, so
        // the walk yields only strictly-forward blocks (no regression, no dup of
        // the requester's own tip).
        let tip = "tip";
        let at = |h: u64| -> Vec<String> {
            match h {
                100 => vec![tip.to_string()],
                101 => vec!["n1".to_string()],
                102 => vec!["n2".to_string()],
                _ => vec![],
            }
        };
        let out = collect_forward_headers(tip, Some(100), 512, at);
        assert_eq!(out, vec!["n1".to_string(), "n2".to_string()]);
    }

    /// Minimal block for selected-chain-walk tests: only hash, parents, and
    /// selected_parent matter to selected_chain_from.
    fn mock_block(hash: &str, parents: &[&str], selected: Option<&str>) -> crate::domain::block::block::Block {
        use crate::domain::block::block::Block;
        use crate::domain::block::block_body::BlockBody;
        use crate::domain::block::block_header::BlockHeader;
        let mut h = BlockHeader::new_with_defaults(
            1,
            hash.to_string(),
            parents.iter().map(|p| p.to_string()).collect(),
            "m".into(),
            0,
            0,
            1,
            1,
        );
        h.selected_parent = selected.map(String::from);
        Block {
            header: h,
            body: BlockBody { transactions: vec![] },
        }
    }

    #[test]
    fn selected_chain_excludes_red_side_blocks() {
        // g -> b1 -> b2(tip) is the selected chain. r2 is a RED sibling of b2
        // (shares parent b1) that must NOT be replayed — its coinbase would
        // otherwise mint inflationary UTXOs on recovery.
        let g = mock_block("g", &[], None);
        let b1 = mock_block("b1", &["g"], Some("g"));
        let b2 = mock_block("b2", &["b1"], Some("b1"));
        let r2 = mock_block("r2", &["b1"], Some("b1")); // red, not on the tip's chain
        let store = |h: &str| match h {
            "g" => Some(g.clone()),
            "b1" => Some(b1.clone()),
            "b2" => Some(b2.clone()),
            "r2" => Some(r2.clone()),
            _ => None,
        };
        let chain = DaemonNode::selected_chain_from(Some("b2".to_string()), store).unwrap();
        let hashes: Vec<&str> = chain.iter().map(|b| b.header.hash.as_str()).collect();
        assert_eq!(hashes, vec!["g", "b1", "b2"], "oldest→newest selected chain only");
        assert!(!hashes.contains(&"r2"), "red side block must be excluded");
    }

    #[test]
    fn selected_chain_uses_first_parent_when_selected_parent_none() {
        // submitblock stores selected_parent=None; resolved_selected_parent
        // falls back to the first PoW-covered parent, so the walk still works.
        let g = mock_block("g", &[], None);
        let b1 = mock_block("b1", &["g"], None);
        let b2 = mock_block("b2", &["b1"], None);
        let store = |h: &str| match h {
            "g" => Some(g.clone()),
            "b1" => Some(b1.clone()),
            "b2" => Some(b2.clone()),
            _ => None,
        };
        let chain = DaemonNode::selected_chain_from(Some("b2".to_string()), store).unwrap();
        let hashes: Vec<&str> = chain.iter().map(|b| b.header.hash.as_str()).collect();
        assert_eq!(hashes, vec!["g", "b1", "b2"]);
    }

    #[test]
    fn selected_chain_broken_walk_returns_none_for_fallback() {
        // A missing ancestor must return None so recovery falls back to the
        // full block set (never rebuilds an INCOMPLETE UTXO state).
        let b2 = mock_block("b2", &["missing"], Some("missing"));
        let store = |h: &str| match h {
            "b2" => Some(b2.clone()),
            _ => None, // "missing" is absent
        };
        assert!(DaemonNode::selected_chain_from(Some("b2".to_string()), store).is_none());
    }

    #[test]
    fn selected_chain_cycle_returns_none() {
        // Corrupt topology (a -> b -> a) must not loop forever.
        let a = mock_block("a", &["b"], Some("b"));
        let b = mock_block("b", &["a"], Some("a"));
        let store = |h: &str| match h {
            "a" => Some(a.clone()),
            "b" => Some(b.clone()),
            _ => None,
        };
        assert!(DaemonNode::selected_chain_from(Some("a".to_string()), store).is_none());
    }

    #[test]
    fn selected_chain_no_tip_is_none() {
        assert!(DaemonNode::selected_chain_from(None, |_| None).is_none());
    }

    #[test]
    fn transient_block_rejections_are_classified_non_penalized() {
        assert!(is_non_penalized_block_rejection(
            "stale template: difficulty mismatch (claimed 4096 expected 3994)"
        ));
        assert!(is_non_penalized_block_rejection(
            "difficulty 3994 outside allowed range [3897, 4091] (expected 3994, tolerance=5%)"
        ));
        assert!(is_non_penalized_block_rejection(
            "stale template: parent set does not intersect current DAG tips"
        ));
    }

    #[test]
    fn hard_invalid_block_rejections_remain_penalized() {
        assert!(!is_non_penalized_block_rejection(
            "block validation failed: merkle root mismatch"
        ));
        assert!(!is_non_penalized_block_rejection(
            "block validation failed: invalid coinbase"
        ));
    }

    fn regtest_cfg_in(dir: std::path::PathBuf) -> NodeConfig {
        let mut cfg = NodeConfig::for_network(NetworkMode::Regtest);
        cfg.data_dir = dir;
        cfg
    }

    /// DURABILITY REGRESSION: UTXO state persisted via `flush_persist` must
    /// survive a full close + reopen of the shared RocksDB (memtable -> SST +
    /// WAL fsync). This is the guarantee that an unclean stop cannot leave the
    /// store effectively empty and force the full-replay crash loop. Guards the
    /// ctrlc-termination + periodic-flush fix.
    #[test]
    fn flushed_utxo_survives_db_reopen() {
        use crate::domain::utxo::utxo_set::utxo_key;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::path::PathBuf::from(format!(
            "{}/shadowdag_reopen_{}",
            std::env::temp_dir().display(),
            ts
        ));
        let n = 4usize;

        let expected;
        {
            let d = DaemonNode::new(regtest_cfg_in(dir.clone()))
                .expect("first daemon open must succeed");
            let base = d.utxo_set.count_utxos();
            for i in 0..n {
                let txh = format!("{:064x}", i + 1);
                let key = utxo_key(&txh, 0).expect("valid utxo key");
                d.utxo_set
                    .add_utxo(&key, format!("owner{}", i), 5_000 + i as u64, format!("owner{}", i));
            }
            expected = base + n;
            assert_eq!(d.utxo_set.count_utxos(), expected, "added UTXOs must be counted");
            d.flush_persist();
        }

        let d2 = DaemonNode::new(regtest_cfg_in(dir))
            .expect("reopen on same data dir must succeed");
        assert_eq!(
            d2.utxo_set.count_utxos(),
            expected,
            "flushed UTXO set must survive a DB close + reopen"
        );
    }
}
