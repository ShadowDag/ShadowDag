// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Shadow Node — A privacy-enhanced relay node that hides the origin of
// transactions. Works like Tor for blockchain transactions:
//
//   1. Receives transactions from other nodes
//   2. Strips identifying metadata (IP, timing, order)
//   3. Mixes with other transactions in the shadow pool
//   4. Relays to the network with randomized timing
//
// Shadow nodes form an onion-like relay network within the ShadowDAG P2P
// layer, making transaction source tracking practically impossible.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::service::network::p2p::peer_manager::PeerManager;
use crate::domain::transaction::transaction::Transaction;
use crate::engine::privacy::shadow_pool::shadow_pool::ShadowPool;
use crate::engine::privacy::shadow_pool::shadow_transaction::MixDelay;
use crate::slog_info;

/// Maximum transactions queued in the shadow relay
pub const MAX_RELAY_QUEUE: usize = 5_000;

/// Minimum transactions before relay emission (anonymity set)
pub const MIN_RELAY_BATCH: usize = 10;

/// Maximum relay delay in milliseconds
pub const MAX_RELAY_DELAY_MS: u64 = 60_000;

/// Shadow node operating mode
#[derive(Debug, Clone, PartialEq)]
pub enum ShadowMode {
    /// Relay only — forward transactions without storing
    Relay,
    /// Mix — actively mix transactions in the shadow pool
    Mix,
    /// Full — relay + mix + validate
    Full,
}

pub struct ShadowNode {
    /// The shadow transaction pool
    pool:            ShadowPool,
    /// Operating mode
    mode:            ShadowMode,
    /// Node's unique (ephemeral) identity — regenerated on restart
    node_id:         String,
    /// Whether the node is active
    active:          bool,
    /// Total transactions relayed
    total_relayed:   u64,
    /// Network name
    network:         String,
}

impl ShadowNode {
    pub fn new(network: &str, mode: ShadowMode) -> Self {
        let mut id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut id_bytes);
        let node_id = hex::encode(id_bytes);

        Self {
            pool: ShadowPool::new(),
            mode,
            node_id,
            active: false,
            total_relayed: 0,
            network: network.to_string(),
        }
    }

    /// Start the shadow node
    pub fn start(&mut self, peers: &PeerManager) {
        self.active = true;

        slog_info!("node", "shadow_node_starting", mode => &format!("{:?}", self.mode), network => &self.network);
        slog_info!("node", "shadow_node_id", id => &self.node_id[..8]);

        let peer_count = peers.count();
        slog_info!("node", "shadow_node_peers", count => &peer_count.to_string());
        slog_info!("node", "shadow_relay_active");
    }

    /// Stop the shadow node
    pub fn stop(&mut self) {
        self.active = false;
        slog_info!("node", "shadow_node_stopped", total_relayed => &self.total_relayed.to_string());
    }

    /// Receive a transaction for relay through the shadow network
    pub fn relay_transaction(&mut self, tx: Transaction) {
        if !self.active {
            return;
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match self.mode {
            ShadowMode::Relay => {
                // Simple relay: add to pool with minimal delay
                self.pool.submit_with_privacy(tx, timestamp, MixDelay::Short, 1);
            }
            ShadowMode::Mix => {
                // Mix mode: full mixing with multiple hops
                self.pool.submit_with_privacy(tx, timestamp, MixDelay::Long, 5);
            }
            ShadowMode::Full => {
                // Full mode: maximum privacy
                self.pool.submit_with_privacy(tx, timestamp, MixDelay::Long, 8);
            }
        }
    }

    /// Process the pool and get transactions ready for network emission
    pub fn emit_ready(&mut self) -> Vec<Transaction> {
        if !self.active {
            return Vec::new();
        }

        let current = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.pool.process(current);
        let ready = self.pool.drain_ready();
        self.total_relayed += ready.len() as u64;
        ready
    }

    /// Generate a relay tag for this node (used in onion routing)
    pub fn relay_tag(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_RelayTag_v1");
        h.update(self.node_id.as_bytes());
        hex::encode(&h.finalize()[..8])
    }

    /// Get node statistics
    pub fn pool_size(&self) -> usize { self.pool.size() }
    pub fn total_relayed(&self) -> u64 { self.total_relayed }
    pub fn is_active(&self) -> bool { self.active }
    pub fn mode(&self) -> &ShadowMode { &self.mode }
    pub fn node_id_short(&self) -> &str { &self.node_id[..8] }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};

    fn make_tx(hash: &str) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: vec![],
            outputs: vec![TxOutput { address: "addr".into(), amount: 100, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    #[test]
    fn new_shadow_node() {
        let node = ShadowNode::new("mainnet", ShadowMode::Full);
        assert!(!node.is_active());
        assert_eq!(node.total_relayed(), 0);
        assert_eq!(*node.mode(), ShadowMode::Full);
    }

    #[test]
    fn relay_when_inactive_is_noop() {
        let mut node = ShadowNode::new("testnet", ShadowMode::Relay);
        node.relay_transaction(make_tx("tx1"));
        assert_eq!(node.pool_size(), 0);
    }

    #[test]
    fn relay_tag_is_deterministic() {
        let node = ShadowNode::new("mainnet", ShadowMode::Mix);
        let tag1 = node.relay_tag();
        let tag2 = node.relay_tag();
        assert_eq!(tag1, tag2);
        assert_eq!(tag1.len(), 16);
    }

    #[test]
    fn node_id_is_unique() {
        let n1 = ShadowNode::new("mainnet", ShadowMode::Mix);
        let n2 = ShadowNode::new("mainnet", ShadowMode::Mix);
        assert_ne!(n1.node_id_short(), n2.node_id_short());
    }
}
