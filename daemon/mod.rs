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

use crate::{slog_error, slog_info, slog_warn};

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
    drain_pending_txs, push_outbound, push_outbound_to_peer, report_bad_peer, report_bad_peer_cat,
    requeue_pending_blocks, requeue_pending_txs, take_orphans_for_parent, P2PMessage, P2P,
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
    orphan_height.saturating_add(crate::engine::consensus::reorg::FINALITY_DEPTH) > best_height
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
    at_height: impl Fn(u64) -> Vec<String>,
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

        // Initialize Stratum pool server if enabled
        let stratum_server = if cfg.enable_stratum {
            slog_info!("daemon", "stratum_init", port => cfg.stratum_port);
            Some(Arc::new(StratumServer::with_rpc_port(cfg.stratum_port, cfg.rpc_port)))
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

        const POLL_INTERVAL: Duration = Duration::from_millis(50);
        const STATS_INTERVAL: Duration = Duration::from_secs(30);
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
        let mut last_sync_req = Instant::now();
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
            if last_sync_req.elapsed() >= std::time::Duration::from_secs(6) {
                last_sync_req = Instant::now();
                let from_hash = self.block_store.get_best_hash().unwrap_or_default();
                push_outbound(P2PMessage::GetHeaders {
                    from_hash,
                    count: 512,
                });
            }

            // ── Drain pending blocks (peer-tagged) ─────────────────
            // Take only BLOCK_BATCH_LIMIT items; return excess to the queue
            // so they're processed on the next tick (no message loss under load).
            let mut blocks = drain_pending_blocks();
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

                            // Broadcast accepted block to peers (gossip propagation)
                            if let Ok(block_bytes) = bincode::serialize(block) {
                                push_outbound(P2PMessage::Block { data: block_bytes });
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
                    if batch_start.elapsed() > std::time::Duration::from_millis(500) {
                        break; // Yield to process pending TXs
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
            }

            // ── Serve block-download requests from peers (chain sync) ──
            // A peer that hit an orphan asks us for the missing ancestor; reply
            // with the block from our store so it can walk the chain forward and
            // converge. Without this, GetBlock is a no-op and forks never heal.
            let block_reqs = drain_block_requests();
            if !block_reqs.is_empty() {
                did_work = true;
                let mut served = 0usize;
                for (req_peer, hash) in block_reqs {
                    if served >= 512 {
                        break; // bound serving work per tick
                    }
                    if let Some(b) = self.block_store.get_block(&hash) {
                        if let Ok(bytes) = bincode::serialize(&b) {
                            push_outbound_to_peer(&req_peer, P2PMessage::Block { data: bytes });
                            served += 1;
                        }
                    }
                }
            }

            // ── Serve header requests: walk the chain FORWARD from from_hash ──
            // and reply with a batch of hashes so a behind/forked peer can bulk-
            // download and catch up (far faster than the sequential orphan-walk).
            let header_reqs = drain_header_requests();
            if !header_reqs.is_empty() {
                did_work = true;
                for (req_peer, from_hash, count) in header_reqs {
                    // Walk forward from the requester's tip, INCLUDING same-height
                    // siblings, so a forked peer receives the canonical sibling it
                    // must adopt to heal (see collect_forward_headers).
                    let from_height = self.block_store.get_block_height(&from_hash);
                    let hashes = collect_forward_headers(&from_hash, from_height, count, |h| {
                        self.block_store.get_block_hashes_at_height(h)
                    });
                    if !hashes.is_empty() {
                        push_outbound_to_peer(&req_peer, P2PMessage::Headers { hashes });
                    }
                }
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

        // Flush RocksDB WAL to prevent corruption
        if let Err(e) = self.db.flush() {
            slog_warn!("daemon", "rocksdb_flush_failed", error => e);
        }
        slog_info!("daemon", "shutdown_complete");
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
        let max_parent_ts = parents
            .iter()
            .filter_map(|h| self.block_store.get_block(h))
            .map(|b| b.header.timestamp)
            .max()
            .unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
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
            version: 1,
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
            // NOTE: we intentionally do NOT compare the per-block stored
            // commitment here. That stored value (`utxo:commitment:{hash}`) is an
            // incremental CHAINED hash — a function of block-apply HISTORY
            // (including reorg order), not of the current UTXO set — so it is
            // structurally incomparable to a snapshot of the live set. The old
            // code compared it against `compute_commitment_hash()` (a set
            // snapshot); those two algorithms can never be equal, so EVERY
            // restart past genesis wiped the UTXO set, replayed, still mismatched
            // and FATAL'd — bricking the node. Until a proper snapshot/Merkle
            // UTXO commitment exists, use the count-based consistency check
            // (the previous pre-commitment behaviour), which is reorg-independent
            // and never false-FATALs.
            slog_info!("daemon", "utxo_count_integrity_check");
            let actual = utxo_count;
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
                        slog_info!("daemon", "utxo_ok_count_based", actual => actual, expected => expected);
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
                    tip => &best_tip[..best_tip.len().min(16)]);
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
}
