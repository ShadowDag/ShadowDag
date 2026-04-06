// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::genesis::genesis::create_genesis_block_for;
use crate::config::node::node_config::{NodeConfig, NetworkMode};
use crate::engine::dag::core::dag_manager::DagManager;
use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;
use crate::infrastructure::storage::rocksdb::core::db::NodeDB;
use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::service::mempool::core::mempool_manager::MempoolManager;
use crate::service::network::p2p::p2p::P2P;
use crate::service::network::relay::tx_relay::sync_mempool as relay_sync_mempool;
use crate::service::network::rpc::rpc_server::RpcServer;
use crate::runtime::node_runtime::runtime_manager::RuntimeManager;

// ✅ إضافات جديدة فقط
use crate::runtime::event_bus::event_bus::EventBus;
use crate::runtime::scheduler::task_scheduler::TaskScheduler;
use crate::runtime::vm::contracts::contract_storage::ContractStorage;
use crate::runtime::vm::gas::gas_meter::GasMeter;

use crate::indexes::utxo_index::UtxoIndex;
use crate::indexes::tx_index::TxIndex;

use std::sync::{Arc, Mutex};
use crate::errors::NodeError;
use crate::{slog_info, slog_warn, slog_error};

/// DEPRECATED: Use DaemonNode::mainnet().start() instead.
/// DaemonNode includes crash recovery, unified FullNode pipeline, and
/// consistent startup behavior. This function remains for test compatibility only.
#[deprecated(note = "Use DaemonNode::new(cfg).start() — includes crash recovery")]
pub fn boot_node() -> Result<(), NodeError> {
    boot_with_config(NodeConfig::for_network(NetworkMode::Mainnet))
}

#[deprecated(note = "Use DaemonNode::testnet().start() — includes crash recovery")]
pub fn boot_testnet_node() -> Result<(), NodeError> {
    boot_with_config(NodeConfig::for_network(NetworkMode::Testnet))
}

#[deprecated(note = "Use DaemonNode::regtest().start() — includes crash recovery")]
pub fn boot_regtest_node() -> Result<(), NodeError> {
    boot_with_config(NodeConfig::for_network(NetworkMode::Regtest))
}

pub fn boot_with_config(cfg: NodeConfig) -> Result<(), NodeError> {
    slog_info!("boot", "node_starting", network => cfg.network.name(), data_dir => cfg.data_dir.display(), p2p_port => cfg.p2p_port, rpc_port => cfg.rpc_port);

    let db_path = cfg.data_dir.join("db");
    let db_path_str = db_path.to_string_lossy().to_string();
    let node_db = NodeDB::new(&db_path_str).map_err(|e| {
        slog_error!("boot", "db_open_failed", error => e);
        NodeError::Storage(e)
    })?;
    let db = node_db.shared();

    // ✅ runtime
    let runtime = RuntimeManager::new(db.clone());
    runtime.start();

    // ✅ إضافات runtime layer (بدون تغيير أي شيء ثاني)
    let _event_bus = EventBus::new(db.clone())
        .map_err(|e| NodeError::Init(format!("Failed to init event bus: {}", e)))?;
    let _scheduler = TaskScheduler::new(db.clone());
    let _contract_storage = ContractStorage::new(db.clone())
        .map_err(|e| NodeError::Init(format!("Failed to init contract storage: {}", e)))?;
    let _gas_meter = GasMeter::new(crate::runtime::vm::gas::gas_rules::MAX_GAS_PER_BLOCK);

    let dag = match DagManager::new(db.clone()) {
        Some(d) => d,
        None => {
            return Err(NodeError::Init("[boot] FATAL: cannot create DAG manager".to_string()));
        }
    };
    let blocks = BlockStore::new(db.clone())
        .map_err(|e| NodeError::Storage(e))?;
    let utxo_store = match UtxoStore::new(db.clone()) {
        Ok(s) => s,
        Err(e) => {
            slog_error!("boot", "utxo_store_failed", error => e);
            return Err(NodeError::Storage(e));
        }
    };
    let utxo_store_arc = Arc::new(utxo_store);
    let utxo_set = UtxoSet::new(utxo_store_arc.clone() as Arc<dyn crate::domain::traits::utxo_backend::UtxoBackend>);

    // Idempotent genesis: only create if no existing chain found
    let existing_best = blocks.get_best_hash();
    if existing_best.is_none() || existing_best.as_deref() == Some("") {
        let genesis = create_genesis_block_for(&cfg.network);
        slog_info!("boot", "genesis_hash", hash => genesis.header.hash);

        let _ = dag.add_block(&genesis);
        blocks.save_block(&genesis);
        blocks.update_best_hash(&genesis.header.hash);

        // Apply genesis UTXO state (coinbase outputs become spendable)
        if let Err(e) = utxo_set.apply_block_full(&genesis, 0) {
            slog_error!("boot", "genesis_utxo_failed", error => e);
            return Err(NodeError::Init(e.to_string()));
        }
        slog_info!("boot", "genesis_created");
    } else {
        // WARNING: boot.rs is DEPRECATED. It does NOT include crash recovery.
        // Use DaemonNode::new(cfg).start() for production — it includes:
        //   - 3-level crash recovery (empty/partial/full UTXO rebuild)
        //   - DAG consistency verification
        //   - Unified FullNode pipeline for genesis
        slog_warn!("boot", "deprecated_boot_path", message => "boot_with_config() lacks crash recovery, use DaemonNode");
        slog_info!("boot", "existing_chain_found", best => existing_best.unwrap_or_default());
    }

    let mut p2p = P2P::new_with_config(&cfg)?;

    p2p.peers.bootstrap_for_network(&cfg.network);
    let _ = p2p.peers.discover_peers();
    slog_info!("boot", "p2p_bootstrapped", peer_count => p2p.peers.count());

    relay_sync_mempool(&p2p.peers);

    let mempool = MempoolManager::new_with_peers_path(db.clone(), &cfg.peers_path_str())
        .map_err(|e| NodeError::Init(e.to_string()))?;

    // Use network-specific peers path to prevent cross-network contamination
    let rpc = RpcServer::new_for_network(cfg.rpc_port, &cfg.peers_path_str(), db.clone())
        .map_err(|e| NodeError::Init(format!("Failed to init RPC server: {}", e)))?;
    rpc.set_network_name(&format!("shadowdag-{}", cfg.network.name()));
    rpc.start();
    slog_info!("boot", "rpc_server_started", port => cfg.rpc_port);

    p2p.start();
    slog_info!("boot", "p2p_listener_started", address => p2p.listen_addr);

    // Initialize persistent indexes with shared DB (auto-recovers from disk)
    let _utxo_index = Arc::new(Mutex::new(UtxoIndex::new_with_db(db.clone())));
    let _tx_index = Arc::new(Mutex::new(TxIndex::new_with_db(db.clone())));

    let _dag = Arc::new(dag);
    let _blocks = Arc::new(blocks);
    let _utxo = Arc::new(utxo_set);
    let _mempool = Arc::new(Mutex::new(mempool));

    slog_info!("boot", "node_running", network => cfg.network.name());
    Ok(())
}
