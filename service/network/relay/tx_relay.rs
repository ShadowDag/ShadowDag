// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Transaction Relay — Broadcasts transactions to peers and manages
// deduplication to prevent redundant network traffic.
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;
use std::sync::Arc;

use crate::errors::NetworkError;
use crate::domain::transaction::transaction::Transaction;
use crate::slog_error;
use crate::service::mempool::core::mempool::Mempool;
use crate::service::network::p2p::p2p::{P2PMessage, push_outbound};
use crate::service::network::p2p::peer_manager::PeerManager;

pub struct TxRelay {
    db:           DB,
    mempool:      Arc<Mempool>,
    _peer_manager: Arc<PeerManager>,
}

impl TxRelay {
    pub fn new(path: &str, mempool: Arc<Mempool>, peer_manager: Arc<PeerManager>) -> Result<Self, NetworkError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| NetworkError::Storage(crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            }))?;
        Ok(Self { db, mempool, _peer_manager: peer_manager })
    }

    /// Broadcast a transaction to all connected peers (with dedup)
    pub fn broadcast_transaction(&self, tx: &Transaction) {
        let key = format!("relay:tx:{}", tx.hash);

        // Skip if already relayed
        if self.db.get(key.as_bytes()).unwrap_or(None).is_some() {
            return;
        }

        // Serialize transaction as bincode for the P2PMessage::Tx payload
        let tx_bytes = match bincode::serialize(tx) {
            Ok(d) => d,
            Err(e) => {
                slog_error!("relay", "tx_serialize_error", error => e);
                return;
            }
        };

        // Push to the global outbound queue — each peer connection thread
        // will drain this queue and send via its TCP stream.
        push_outbound(P2PMessage::Tx { data: tx_bytes });

        // Mark AFTER successful queue push
        if let Err(e) = self.db.put(key.as_bytes(), b"1") {
            slog_error!("relay", "tx_relay_db_put_error", error => e);
        }

        log::debug!("[TxRelay] Queued tx {} for broadcast", &tx.hash[..8]);
    }

    /// Receive a transaction from a peer — validate BEFORE relay.
    /// Only transactions that pass mempool validation are relayed to other peers.
    /// This prevents DoS amplification attacks with invalid transactions.
    pub fn receive_transaction(&self, tx: Transaction) {
        let key = format!("relay:tx:{}", tx.hash);

        // Skip if already seen
        if self.db.get(key.as_bytes()).unwrap_or(None).is_some() {
            return;
        }

        // VALIDATE FIRST — add to mempool (which verifies signatures + balance)
        let accepted = self.mempool.add_transaction(&tx);

        // Only mark as seen AND relay if the transaction was accepted
        if accepted {
            if let Err(e) = self.db.put(key.as_bytes(), b"1") {
                slog_error!("relay", "tx_relay_db_put_error", error => e);
            }

            let tx_bytes = match bincode::serialize(&tx) {
                Ok(d) => d,
                Err(_) => return,
            };
            push_outbound(P2PMessage::Tx { data: tx_bytes });
        }
        // Invalid TX: NOT marked as seen, so if corrected it can be resubmitted
    }
}

/// Standalone broadcast function for simple use cases
pub fn broadcast(tx: &Transaction, _peers: &PeerManager) {
    let tx_bytes = match bincode::serialize(tx) {
        Ok(d) => d,
        Err(_) => return,
    };

    push_outbound(P2PMessage::Tx { data: tx_bytes });
}

/// Request mempool contents from peers during initial sync.
/// Uses the dedicated GetMempool message type — GetData only accepts
/// "block" and "tx" as valid inv item kinds, so `kind: "mempool"`
/// would be rejected by the protocol validator on the receiving peer.
pub fn sync_mempool(_peers: &PeerManager) {
    push_outbound(P2PMessage::GetMempool);
    log::debug!("[TxRelay] Requested mempool sync from peers");
}
