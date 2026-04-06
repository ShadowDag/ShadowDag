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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use parking_lot::Mutex;

use rocksdb::DB;

use crate::{slog_info, slog_warn, slog_error};

use crate::config::genesis::genesis::create_genesis_block_for;
use crate::config::node::node_config::{NodeConfig, NetworkMode};
use crate::engine::dag::core::dag_manager::DagManager;
use crate::engine::dag::ghostdag::ghostdag::GhostDag;
use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;
use crate::infrastructure::storage::rocksdb::core::db::NodeDB;
use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::runtime::node_runtime::lifecycle::Lifecycle;
use crate::service::mempool::core::mempool_manager::MempoolManager;
use crate::service::mempool::pools::tx_pool::TxPoolResult;
use crate::service::network::nodes::full_node::FullNode;
use crate::service::network::p2p::p2p::{P2P, P2PMessage, push_outbound, drain_pending_txs, drain_pending_blocks, report_bad_peer, report_bad_peer_cat};
use crate::engine::dag::security::dag_shield::DagShield;
use crate::service::network::dos_guard::BanCategory;
use crate::service::network::rpc::rpc_server::RpcServer;
use crate::engine::consensus::finality::FinalityManager;

use crate::indexes::utxo_index::UtxoIndex;
use crate::indexes::tx_index::TxIndex;
use crate::errors::NodeError;

/// Sentinel substrings used to classify block-rejection errors.
/// Centralised here so a single rename propagates to every check.
const ERR_ALREADY_EXISTS: &str = "already exists";
const ERR_ORPHAN: &str = "ORPHAN";

/// Ban score for peers that send invalid blocks rejected by consensus.
const BAN_SCORE_INVALID_BLOCK: u64 = 20;
/// Ban score for peers that send invalid transactions rejected by mempool.
const BAN_SCORE_INVALID_TX: u64 = 5;

pub struct DaemonNode {
    cfg:         NodeConfig,
    db:          Arc<DB>,
    /// The unified block processing engine — ALL block operations go through here
    full_node:   Arc<FullNode>,
    /// Direct access to stores (for genesis init + RPC)
    block_store: Arc<BlockStore>,
    utxo_set:    Arc<UtxoSet>,
    dag:         Arc<DagManager>,
    ghostdag:    Arc<GhostDag>,
    mempool:     Arc<Mutex<MempoolManager>>,
    /// UTXO index (in-memory cache backed by RocksDB)
    utxo_index:  Arc<Mutex<UtxoIndex>>,
    /// TX index (in-memory cache backed by RocksDB)
    tx_index:    Arc<Mutex<TxIndex>>,
    /// Dynamic finality manager — adjusts finality depth based on DAG health
    finality_manager: Mutex<FinalityManager>,
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
                return Err(NodeError::Init(format!("[daemon] FATAL: cannot create DAG manager at {}", db_path_str)));
            }
        };

        let block_store = Arc::new(BlockStore::new(db.clone())
            .map_err(|e| NodeError::Init(format!("[daemon] FATAL: cannot create block store: {}", e)))?);

        let utxo_store = Arc::new(
            UtxoStore::new(db.clone()).map_err(|e| {
                NodeError::Init(format!("[daemon] FATAL: cannot create UTXO store: {}", e))
            })?
        );
        let utxo_set = Arc::new(UtxoSet::new(utxo_store.clone() as Arc<dyn crate::domain::traits::utxo_backend::UtxoBackend>));

        // GhostDag shares the node's single RocksDB instance.
        // All GhostDag keys are namespaced with "gd:" to avoid collisions.
        let ghostdag = Arc::new(GhostDag::new_with_db(db.clone()));

        let mempool = Arc::new(Mutex::new(
            MempoolManager::new_with_peers_path(db.clone(), &cfg.peers_path_str())
                .map_err(|e| NodeError::Init(format!("Failed to init mempool: {}", e)))?
        ));

        // Create the unified block processing engine
        let full_node = Arc::new(FullNode::new(
            block_store.clone(),
            utxo_set.clone(),
            dag.clone(),
            ghostdag.clone(),
            cfg.network.clone(),
        ));

        // Initialize persistent indexes with shared DB (auto-recovers from disk)
        let utxo_index = Arc::new(Mutex::new(UtxoIndex::new_with_db(db.clone())));
        let tx_index = Arc::new(Mutex::new(TxIndex::new_with_db(db.clone())));

        // Initialize dynamic finality manager (10 BPS default)
        let mut finality_mgr = FinalityManager::new(10);
        finality_mgr = finality_mgr.with_db(db.clone());
        finality_mgr.load_checkpoints();

        Ok(Self {
            cfg,
            db,
            full_node,
            block_store,
            utxo_set,
            dag,
            ghostdag,
            mempool,
            utxo_index,
            tx_index,
            finality_manager: Mutex::new(finality_mgr),
        })
    }

    pub fn mainnet()  -> Result<Self, NodeError> { Self::new(NodeConfig::for_network(NetworkMode::Mainnet)) }
    pub fn testnet()  -> Result<Self, NodeError> { Self::new(NodeConfig::for_network(NetworkMode::Testnet)) }
    pub fn regtest()  -> Result<Self, NodeError> { Self::new(NodeConfig::for_network(NetworkMode::Regtest)) }

    pub fn start(&mut self) -> Result<(), NodeError> {
        Lifecycle::on_start();
        self.print_banner();

        // ── Genesis initialization (idempotent) ──────────────────
        let existing_best = self.block_store.get_best_hash();
        if existing_best.is_none() || existing_best.as_deref() == Some("") {
            let genesis = create_genesis_block_for(&self.cfg.network);
            slog_info!("daemon", "genesis_hash", hash => genesis.header.hash);

            // Genesis goes through FullNode::process_genesis() — SAME pipeline
            // as all other blocks (validate, save, DAG, GHOSTDAG, UTXO, best_hash).
            // Only difference: parent validation skipped (genesis has no parents).
            self.full_node.process_genesis(&genesis)
                .map_err(|e| NodeError::Init(format!("[daemon] FATAL: genesis processing failed: {}", e)))?;
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
        let mut p2p = P2P::new_with_config(&self.cfg)?;
        p2p.peers.bootstrap_for_network(&self.cfg.network);
        let _ = p2p.peers.discover_peers();
        slog_info!("daemon", "p2p_bootstrapped", peers => p2p.peers.count());

        // ── RPC ──────────────────────────────────────────────────
        let rpc = RpcServer::new_for_network(
            self.cfg.rpc_port,
            &self.cfg.peers_path_str(),
            self.db.clone(),
        ).map_err(|e| NodeError::Init(format!("Failed to init RPC server: {}", e)))?;
        rpc.set_network_name(&format!("shadowdag-{}", self.cfg.network.name()));
        rpc.set_network_ports(self.cfg.p2p_port, self.cfg.rpc_port);
        rpc.start();
        slog_info!("daemon", "rpc_started", port => self.cfg.rpc_port);

        // ── Start network ────────────────────────────────────────
        p2p.start();
        slog_info!("daemon", "p2p_listening", addr => p2p.listen_addr);

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
        const TX_BATCH_LIMIT: usize = 500;   // Max TXs per tick (backpressure)
        const BLOCK_BATCH_LIMIT: usize = 50;  // Max blocks per tick

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
        let mut total_blocks_processed: u64 = 0;
        let mut total_txs_processed: u64 = 0;
        let mut total_blocks_rejected: u64 = 0;
        let mut total_txs_rejected: u64 = 0;

        slog_info!("daemon", "event_loop_started", poll_interval_ms => POLL_INTERVAL.as_millis());

        while !shutdown.load(Ordering::SeqCst) {
            let mut did_work = false;

            // ── Drain pending blocks (peer-tagged) ─────────────────
            let blocks = drain_pending_blocks();
            if !blocks.is_empty() {
                did_work = true;
                let batch_start = std::time::Instant::now();
                for (peer_id, block) in blocks.into_iter().take(BLOCK_BATCH_LIMIT) {
                    let hash_prefix = if block.header.hash.len() >= 16 {
                        &block.header.hash[..16]
                    } else {
                        &block.header.hash
                    };

                    // ── DagShield safety net (defense-in-depth) ──
                    // P2P dispatch already calls pre_validate_block, but the event
                    // loop is the LAST gate before FullNode — catch anything that
                    // slipped through (e.g. RPC-submitted blocks, future code paths).
                    if let Err(rej) = DagShield::pre_validate_block(&block) {
                        total_blocks_rejected += 1;
                        report_bad_peer(&peer_id, rej.ban_score as u64, rej.reason);
                        slog_warn!("daemon", "block_rejected_dagshield", hash => hash_prefix, reason => rej.reason);
                        continue;
                    }

                    match self.full_node.process_block(&block) {
                        Ok(()) => {
                            total_blocks_processed += 1;
                            slog_info!("daemon", "block_processed", hash => hash_prefix, height => block.header.height, txs => block.body.transactions.len());

                            // Notify finality manager of new accepted block
                            // Simplified: assume accepted block is blue, dag_width=1
                            self.finality_manager.lock().on_block(
                                block.header.height,
                                &block.header.hash,
                                true,
                                1,
                            );

                            // Broadcast accepted block to peers (gossip propagation)
                            if let Ok(block_bytes) = bincode::serialize(&block) {
                                push_outbound(P2PMessage::Block { data: block_bytes });
                            }
                        }
                        Err(e) => {
                            total_blocks_rejected += 1;
                            let err_msg = e.to_string();
                            // "already exists" is normal during sync — don't penalize
                            if !err_msg.contains(ERR_ALREADY_EXISTS) && !err_msg.contains(ERR_ORPHAN) {
                                // Ban feedback: penalize peer that sent the bad block
                                report_bad_peer_cat(&peer_id, BAN_SCORE_INVALID_BLOCK, "invalid block rejected by consensus", BanCategory::Malformed);
                                slog_error!("daemon", "block_rejected_consensus", hash => hash_prefix, peer => peer_id, error => err_msg);
                            }
                        }
                    }

                    if batch_start.elapsed() > std::time::Duration::from_millis(500) {
                        break; // Yield to process pending TXs
                    }
                }
            }

            // ── Drain pending transactions (peer-tagged) ────────────
            let txs = drain_pending_txs();
            if !txs.is_empty() {
                did_work = true;
                {
                    let mut mempool = self.mempool.lock();
                    for (peer_id, tx) in txs.into_iter().take(TX_BATCH_LIMIT) {
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
                            _ => {
                                total_txs_rejected += 1;
                                // Ban feedback: penalize peer sending invalid TXs
                                report_bad_peer_cat(&peer_id, BAN_SCORE_INVALID_TX, "invalid tx rejected by mempool", BanCategory::Malformed);
                            }
                        }
                    }
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
    pub fn process_block(&self, block: &crate::domain::block::block::Block) -> Result<(), NodeError> {
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
        let best_hash = self.block_store.get_best_hash()
            .ok_or(NodeError::Init("No best hash found".to_string()))?;
        let best_block = self.block_store.get_block(&best_hash)
            .ok_or(NodeError::Init("Best block not found in store".to_string()))?;
        slog_info!("daemon", "recovery_blockstore_ok",
            best => &best_hash[..std::cmp::min(16, best_hash.len())],
            height => best_block.header.height);

        // Step B: Check DAG + GHOSTDAG consistency
        let dag_ok = self.dag.block_exists(&best_hash);
        let ghostdag_ok = self.ghostdag.get_blue_score(&best_hash) > 0
            || best_block.header.height == 0;

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
            // Level 2: full UTXO commitment verification
            // Instead of just comparing counts, compute a commitment hash over
            // ALL UTXO data (txid, index, amount, owner, maturity) and compare
            // with the commitment stored in the best block header.
            slog_info!("daemon", "utxo_commitment_check");

            // Try UTXO store commitment first (atomic with UTXO apply),
            // then BlockStore (legacy), then header field (oldest legacy).
            let stored_commitment = self.utxo_set.get_commitment(&best_block.header.hash)
                .or_else(|| self.block_store.get_utxo_commitment(&best_block.header.hash))
                .or_else(|| best_block.header.utxo_commitment.clone())
                .unwrap_or_default();
            let computed_commitment = self.utxo_set.compute_commitment_hash();

            if stored_commitment.is_empty() {
                // No commitment anywhere — fall back to count-based check
                // (for blocks processed before commitment was added)
                slog_info!("daemon", "utxo_no_commitment_fallback_count_check");
                let expected = self.compute_expected_utxo_count();
                let actual = utxo_count;
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
            } else if computed_commitment != stored_commitment {
                // Commitment mismatch — UTXO state is corrupted (amounts, owners,
                // spent flags, or maturity could be wrong even if count matches)
                slog_error!("daemon", "utxo_commitment_mismatch_rebuilding",
                    stored => &stored_commitment[..std::cmp::min(16, stored_commitment.len())],
                    computed => &computed_commitment[..std::cmp::min(16, computed_commitment.len())]
                );
                self.utxo_set.clear_all();
                self.replay_blocks()?;

                // Verify commitment after rebuild
                let rebuilt_commitment = self.utxo_set.compute_commitment_hash();
                if rebuilt_commitment != stored_commitment {
                    return Err(NodeError::Init(format!(
                        "UTXO commitment still mismatches after full replay! \
                         This indicates BlockStore corruption. stored={}, rebuilt={}",
                        &stored_commitment[..std::cmp::min(16, stored_commitment.len())],
                        &rebuilt_commitment[..std::cmp::min(16, rebuilt_commitment.len())]
                    )));
                }
                slog_info!("daemon", "utxo_rebuilt_and_verified", entries => self.utxo_set.count_utxos());
            } else {
                slog_info!("daemon", "utxo_ok_commitment_verified",
                    entries => utxo_count,
                    hash => &computed_commitment[..std::cmp::min(16, computed_commitment.len())]);
            }
        } else {
            slog_info!("daemon", "utxo_ok", entries => utxo_count);
        }

        slog_info!("daemon", "recovery_all_subsystems_verified");
        Ok(())
    }

    /// Rebuild DAG topology from all blocks in BlockStore.
    fn rebuild_dag(&self) -> Result<(), NodeError> {
        slog_info!("daemon", "dag_rebuild_start");
        let blocks = self.block_store.get_all_blocks_sorted_by_height();
        let total = blocks.len() as u64;
        let mut failed = 0u64;
        let max_failures = std::cmp::min(100, std::cmp::max(1, total / 10));
        for block in &blocks {
            // Use validated=true since these blocks were already accepted
            if let Err(e) = self.dag.add_block_validated(block, true) {
                failed += 1;
                slog_warn!("daemon", "dag_rebuild_block_failed",
                    hash => block.header.hash,
                    height => block.header.height,
                    error => e
                );
                if failed > max_failures {
                    return Err(NodeError::Init(format!(
                        "DAG rebuild aborted: {} failures exceeds threshold {} (of {} blocks)",
                        failed, max_failures, total
                    )));
                }
            }
        }
        if failed > 0 {
            slog_warn!("daemon", "dag_rebuild_partial_failure", failed => failed);
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
        let max_failures = std::cmp::min(100, std::cmp::max(1, total / 10));
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
            if let Err(e) = result {
                failed += 1;
                let msg = e.downcast_ref::<String>()
                    .map(|s| s.as_str())
                    .or_else(|| e.downcast_ref::<&str>().copied())
                    .unwrap_or("unknown panic");
                slog_warn!("daemon", "ghostdag_rebuild_block_failed",
                    hash => block.header.hash,
                    height => block.header.height,
                    error => msg
                );
                if failed > max_failures {
                    return Err(NodeError::Init(format!(
                        "GHOSTDAG rebuild aborted: {} failures exceeds threshold {} (of {} blocks)",
                        failed, max_failures, total
                    )));
                }
            }
        }
        if failed > 0 {
            slog_warn!("daemon", "ghostdag_rebuild_partial_failure", failed => failed);
        }

        // Re-derive best tip from GHOSTDAG blue scores
        let tips = self.ghostdag.get_tips();
        if let Some(best_tip) = tips.first() {
            self.block_store.update_best_hash(best_tip);
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

    /// Replay all blocks from height 0 to rebuild UTXO state.
    fn replay_blocks(&self) -> Result<(), NodeError> {
        slog_info!("daemon", "utxo_replay_start");
        let blocks = self.block_store.get_all_blocks_sorted_by_height();
        for block in &blocks {
            self.utxo_set.apply_block_full(block, block.header.height)
                .map_err(|e| NodeError::Init(format!("replay failed at height {}: {}",
                    block.header.height, e)))?;
        }
        slog_info!("daemon", "utxo_replay_complete", blocks => blocks.len());
        Ok(())
    }

    /// Compute expected UTXO count by walking all blocks.
    /// For each block: outputs created - inputs spent = net change.
    /// Sum all net changes = expected unspent UTXO count.
    fn compute_expected_utxo_count(&self) -> usize {
        let blocks = self.block_store.get_all_blocks_sorted_by_height();
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

        total_created.saturating_sub(total_spent)
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
            "{}/shadowdag_test_{}_{}", std::env::temp_dir().display(), cfg.network.short_name(), ts
        ));
        DaemonNode::new(cfg).expect("failed to create DaemonNode for test — check NodeConfig and data_dir permissions")
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
}
