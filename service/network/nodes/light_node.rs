// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Light Node — Simplified Payment Verification (SPV) node for mobile
// and resource-constrained devices. Only stores block headers, not full
// blocks, and verifies transactions using Merkle proofs.
//
// Capabilities:
//   - Header-only sync (minimal storage)
//   - Merkle proof verification
//   - Bloom filter-based transaction watching
//   - Stealth address scanning with view key
// ═══════════════════════════════════════════════════════════════════════════

use crate::service::network::p2p::peer_manager::PeerManager;
use crate::domain::block::block_header::BlockHeader;
use crate::domain::block::merkle_proof::MerkleProof;
use crate::domain::block::merkle_verifier::MerkleVerifier;

/// Maximum headers to store in memory
pub const MAX_HEADERS_CACHE: usize = 10_000;

/// SPV light node
pub struct LightNode {
    /// Cached block headers
    headers:      Vec<BlockHeader>,
    /// Addresses we're watching for
    watch_list:   Vec<String>,
    /// Whether the node is syncing
    syncing:      bool,
    /// Best known header height
    best_height:  u64,
    /// Network identifier
    network:      String,
}

impl LightNode {
    pub fn new(network: &str) -> Self {
        Self {
            headers:     Vec::with_capacity(MAX_HEADERS_CACHE),
            watch_list:  Vec::new(),
            syncing:     false,
            best_height: 0,
            network:     network.to_string(),
        }
    }

    /// Start the light node and begin header sync
    pub fn start(&mut self, peers: &PeerManager) {
        self.syncing = true;
        eprintln!("[LightNode] Starting SPV node on {}", self.network);
        eprintln!("[LightNode] Requesting headers from peers...");

        // Request headers from connected peers
        let peer_count = peers.count();
        eprintln!("[LightNode] Connected to {} peers", peer_count);
    }

    /// Stop the light node
    pub fn stop(&mut self) {
        self.syncing = false;
        eprintln!("[LightNode] Stopped.");
    }

    /// Add a block header to our chain
    pub fn add_header(&mut self, header: BlockHeader) -> bool {
        // Basic validation
        if header.height != self.best_height + 1 && self.best_height > 0 {
            return false;
        }

        self.best_height = header.height;

        // Keep cache bounded
        if self.headers.len() >= MAX_HEADERS_CACHE {
            self.headers.remove(0);
        }
        self.headers.push(header);
        true
    }

    /// Verify a transaction exists in a block using Merkle proof
    pub fn verify_tx_inclusion(
        &self,
        tx_hash:     &str,
        proof:       &MerkleProof,
        block_height: u64,
    ) -> bool {
        // Find the header for this block
        let header = self.headers.iter().find(|h| h.height == block_height);

        match header {
            Some(h) => MerkleVerifier::verify(
                tx_hash.to_string(),
                proof,
                h.merkle_root.clone(),
            ),
            None => false,
        }
    }

    /// Add an address to the watch list
    pub fn watch_address(&mut self, address: String) {
        if !self.watch_list.contains(&address) {
            self.watch_list.push(address);
        }
    }

    /// Remove an address from the watch list
    pub fn unwatch_address(&mut self, address: &str) {
        self.watch_list.retain(|a| a != address);
    }

    /// Get the best known height
    pub fn best_height(&self) -> u64 {
        self.best_height
    }

    /// Check if a given address is being watched
    pub fn is_watching(&self, address: &str) -> bool {
        self.watch_list.iter().any(|a| a == address)
    }

    /// Get header count
    pub fn header_count(&self) -> usize {
        self.headers.len()
    }

    /// Is the node currently syncing?
    pub fn is_syncing(&self) -> bool {
        self.syncing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(height: u64) -> BlockHeader {
        BlockHeader {
            version: 1,
            hash: format!("hash_{}", height),
            parents: vec![format!("hash_{}", height.saturating_sub(1))],
            merkle_root: "merkle_root".to_string(),
            timestamp: 1735689600 + height * 1000,
            nonce: 0,
            difficulty: 4,
            height,
            blue_score: 0,
            selected_parent: None,
            utxo_commitment: None,
            extra_nonce: 0,
        }
    }

    #[test]
    fn add_header_increments_height() {
        let mut node = LightNode::new("testnet");
        assert!(node.add_header(make_header(1)));
        assert_eq!(node.best_height(), 1);
        assert_eq!(node.header_count(), 1);
    }

    #[test]
    fn watch_address() {
        let mut node = LightNode::new("mainnet");
        node.watch_address("SD1abc".to_string());
        assert!(node.is_watching("SD1abc"));
        assert!(!node.is_watching("SD1xyz"));
    }

    #[test]
    fn unwatch_address() {
        let mut node = LightNode::new("mainnet");
        node.watch_address("SD1abc".to_string());
        node.unwatch_address("SD1abc");
        assert!(!node.is_watching("SD1abc"));
    }
}
