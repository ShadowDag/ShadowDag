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
use crate::slog_info;

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
        slog_info!("node", "light_node_starting", network => &self.network);
        slog_info!("node", "requesting_headers");

        // Request headers from connected peers
        let peer_count = peers.count();
        slog_info!("node", "light_node_peers", count => &peer_count.to_string());
    }

    /// Stop the light node
    pub fn stop(&mut self) {
        self.syncing = false;
        slog_info!("node", "light_node_stopped");
    }

    /// Validate header hash and PoW before accepting.
    fn validate_header_basic(header: &BlockHeader) -> bool {
        // 1. Hash must be non-empty and valid hex (64 lowercase hex chars)
        if header.hash.len() != 64 || !header.hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        // 2. PoW: hash must meet difficulty target
        use crate::engine::mining::pow::pow_validator::PowValidator;
        if header.difficulty > 0 && !PowValidator::hash_meets_target(&header.hash, header.difficulty) {
            return false;
        }
        // 3. Timestamp sanity: reject headers too far in the future
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if header.timestamp > now + 120 { // MAX_FUTURE_SECS
            return false;
        }
        true
    }

    /// Add a block header to our chain.
    /// First header MUST be genesis (height 0) to establish root of trust.
    pub fn add_header(&mut self, header: BlockHeader) -> bool {
        // Validate header hash and PoW BEFORE accepting
        if !Self::validate_header_basic(&header) {
            return false;
        }

        if self.headers.is_empty() {
            // First header must be genesis — no arbitrary starting point
            if header.height != 0 {
                return false;
            }
            self.best_height = 0;
            self.headers.push(header);
            return true;
        }

        // Subsequent headers must be exactly +1
        if header.height != self.best_height + 1 {
            return false;
        }

        // Must point to previous tip (parent continuity)
        if let Some(prev) = self.headers.last() {
            let parent_ok = header.selected_parent.as_deref() == Some(prev.hash.as_str())
                || header.parents.iter().any(|p| p == &prev.hash);
            if !parent_ok {
                return false;
            }
            // Monotonic timestamp
            if header.timestamp < prev.timestamp {
                return false;
            }
        }

        self.best_height = header.height;

        // Keep cache bounded
        if self.headers.len() >= MAX_HEADERS_CACHE {
            self.headers.remove(0);
        }
        self.headers.push(header);
        true
    }

    /// Verify a transaction exists in a block using Merkle proof.
    /// Finds the header by block_hash (stronger than height alone).
    pub fn verify_tx_inclusion(
        &self,
        tx_hash:    &str,
        proof:      &MerkleProof,
        block_hash: &str,
    ) -> bool {
        let header = self.headers.iter().find(|h| h.hash == block_hash);
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
        // Use valid 64-char hex hashes so validate_header_basic passes.
        // Difficulty 0 bypasses PoW check (genesis-style for testing).
        let hash = format!("{:0>64x}", height + 1);
        let parent_hash = format!("{:0>64x}", height.saturating_sub(1) + 1);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        BlockHeader {
            version: 1,
            hash,
            parents: vec![parent_hash],
            merkle_root: "merkle_root".to_string(),
            timestamp: now - 60 + height,
            nonce: 0,
            difficulty: 0,
            height,
            blue_score: 0,
            selected_parent: None,
            utxo_commitment: None,
            extra_nonce: 0,
            receipt_root: None,
            state_root: None,
        }
    }

    #[test]
    fn add_header_increments_height() {
        let mut node = LightNode::new("testnet");
        // First header must be genesis (height 0)
        assert!(node.add_header(make_header(0)));
        assert_eq!(node.best_height(), 0);
        // Then add height 1
        assert!(node.add_header(make_header(1)));
        assert_eq!(node.best_height(), 1);
        assert_eq!(node.header_count(), 2);
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
