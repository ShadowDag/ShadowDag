// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::sync::Arc;
use rocksdb::DB;

use crate::errors::MempoolError;
use crate::runtime::event_bus::event_bus::EventBus; // ✅ إضافة

use crate::domain::transaction::transaction::Transaction;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::engine::dag::security::dos_protection::DosProtection;
use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
use crate::service::mempool::core::mempool::Mempool;
use crate::service::mempool::pools::tx_pool::{TxPool, TxPoolResult};
use crate::service::mempool::pools::orphan_pool::OrphanPool;
use crate::service::mempool::fees::fee_market::FeeMarket;
use crate::service::network::p2p::p2p::{P2PMessage, push_outbound_to_peer};
use crate::service::network::p2p::peer_manager::PeerManager;
use crate::service::network::relay::tx_relay::broadcast as tx_broadcast;
use crate::service::network::propagation::dandelion::{DandelionRelay, RelayAction};

pub struct MempoolManager {
    pub tx_pool:     TxPool,
    pub orphan_pool: OrphanPool,
    utxo_set:        UtxoSet,
    peer_manager:    PeerManager,
    current_height:  u64,
    dandelion:       DandelionRelay,

    event_bus: EventBus, // ✅ إضافة
}

impl MempoolManager {
    pub fn new(db: Arc<DB>) -> Result<Self, MempoolError> {
        let peers_path = crate::config::node::node_config::NetworkMode::base_data_dir()
            .join("peers");
        Self::new_with_peers_path(db, &peers_path.to_string_lossy())
    }

    pub fn new_with_peers_path(db: Arc<DB>, peers_path: &str) -> Result<Self, MempoolError> {
        let utxo_store = Arc::new(
            UtxoStore::new(db.clone())
                .map_err(|e| MempoolError::Storage(crate::errors::StorageError::OpenFailed {
                    path: "utxo_store".to_string(),
                    reason: e.to_string(),
                }))?
        );
        let mempool    = Mempool::new(db.clone())
            .map_err(|e| MempoolError::Storage(crate::errors::StorageError::Other(e.to_string())))?;
        Ok(Self {
            tx_pool:        TxPool::new(mempool),
            orphan_pool:    OrphanPool::new(),
            utxo_set:       UtxoSet::new(utxo_store as Arc<dyn crate::domain::traits::utxo_backend::UtxoBackend>),
            peer_manager:   PeerManager::new_default_path(peers_path)
                .map_err(|e| MempoolError::Storage(crate::errors::StorageError::Other(e.to_string())))?,
            current_height: 0,
            dandelion:      DandelionRelay::new(),

            event_bus: EventBus::new(db.clone())
                .map_err(|e| MempoolError::Storage(e))?,
        })
    }

    pub fn initialize(&self) {
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> TxPoolResult {
        let dos = DosProtection::validate_transaction(&tx);
        if !dos.is_ok() {
            return TxPoolResult::Rejected;
        }

        let result = self.tx_pool.add_transaction(&tx, &self.utxo_set);

        match &result {
            TxPoolResult::Accepted => {
                // Dandelion++ privacy relay: decide stem or fluff
                let peers = self.peer_manager.get_peers();
                let action = self.dandelion.on_new_tx_with_peers(&tx.hash, None, &peers);
                match action {
                    RelayAction::StemTo(stem_peer) => {
                        // Stem phase: send to EXACTLY ONE peer for privacy
                        if let Ok(tx_bytes) = bincode::serialize(&tx) {
                            push_outbound_to_peer(&stem_peer, P2PMessage::Tx { data: tx_bytes });
                        }
                        log::debug!("[Dandelion] TX {} stem → {}", &tx.hash[..8], stem_peer);
                    }
                    RelayAction::Fluff => {
                        // Fluff phase: broadcast to all peers
                        tx_broadcast(&tx, &self.peer_manager);
                    }
                    RelayAction::Drop => {
                        // Already seen — skip broadcast
                    }
                }

                // ✅ event publish
                self.event_bus.publish(&tx.hash, "tx:new");

                self.promote_orphans(&tx.hash);
            }
            TxPoolResult::Orphan => {
                self.orphan_pool.add(tx.clone(), self.current_height);
            }
            TxPoolResult::Duplicate => {
            }
            TxPoolResult::DoubleSpend => {
            }
            TxPoolResult::Invalid | TxPoolResult::Rejected => {
            }
        }

        result
    }

    pub fn collect_for_block(&self, limit: usize) -> Vec<Transaction> {
        self.tx_pool.mempool.select_transactions_for_block(&self.utxo_set, limit)
    }

    pub fn on_new_block(&mut self, height: u64, confirmed_txids: &[String]) {
        self.current_height = height;

        for txid in confirmed_txids {
            self.tx_pool.remove_transaction(txid);
        }

        self.orphan_pool.evict_old(height);
    }

    pub fn suggested_fee(&self) -> u64 {
        FeeMarket::suggested_fee(&self.tx_pool.mempool)
    }

    pub fn stats(&self) {
        let _s = self.tx_pool.mempool.stats();
    }

    fn promote_orphans(&mut self, parent_txid: &str) {
        let promoted = self.orphan_pool.promote(parent_txid);
        for tx in promoted {
            let _result = self.tx_pool.add_transaction(&tx, &self.utxo_set);
        }
    }
}