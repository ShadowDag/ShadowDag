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

use crate::domain::block::block_header::BlockHeader;
use crate::domain::block::merkle_proof::MerkleProof;
use crate::domain::block::merkle_verifier::MerkleVerifier;
use crate::service::network::p2p::peer_manager::PeerManager;
use crate::slog_info;

/// Maximum headers to store in memory
pub const MAX_HEADERS_CACHE: usize = 10_000;

/// SPV light node
pub struct LightNode {
    /// Cached block headers
    headers: Vec<BlockHeader>,
    /// Addresses we're watching for
    watch_list: Vec<String>,
    /// Whether the node is syncing
    syncing: bool,
    /// Best known header height
    best_height: u64,
    /// Network identifier
    network: String,
    /// Parsed network, when `network` names a known one. `None` = the node could
    /// not resolve its network, so it also has no genesis hash and is degraded /
    /// NON-AUTHORITATIVE: it cannot enforce the UmbraHash activation schedule.
    network_mode: Option<crate::config::node::node_config::NetworkMode>,
    /// Known genesis hash for this network
    genesis_hash: String,
}

impl LightNode {
    pub fn new(network: &str) -> Self {
        // Resolve the network ONCE: it gives us both the known genesis hash (to
        // verify the first header) and the UmbraHash activation schedule (so we
        // reject a downgraded legacy header past the fork instead of recomputing
        // it under the network-blind rule).
        let network_mode = network
            .parse::<crate::config::node::node_config::NetworkMode>()
            .ok();
        let genesis_hash = network_mode
            .as_ref()
            .map(crate::config::genesis::genesis::genesis_hash_for)
            .unwrap_or_default();
        Self {
            headers: Vec::with_capacity(MAX_HEADERS_CACHE),
            watch_list: Vec::new(),
            syncing: false,
            best_height: 0,
            network: network.to_string(),
            network_mode,
            genesis_hash,
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

    /// CHEAP header checks — no hashing, no epoch cache. Must pass before any
    /// identity recompute (external audit H3: an unvalidated header must never be
    /// able to trigger `epoch_seed`/`mkcache` work before it has been screened).
    fn validate_header_cheap(header: &BlockHeader) -> bool {
        // Hash must be non-empty and valid hex (64 lowercase hex chars)
        if header.hash.len() != 64 || !header.hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        // Reject difficulty=0 on non-genesis headers — it bypasses PoW entirely.
        if header.height > 0 && header.difficulty == 0 {
            return false;
        }
        // Timestamp sanity: reject headers too far in the future.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        // Header timestamps are epoch MILLISECONDS; the future bound must be in ms
        // (120 s = 120_000 ms), else every real ms header is rejected as "future"
        // and SPV header sync never accepts a single header (B4-L03).
        if header.timestamp > now + 120_000 {
            return false;
        }
        true
    }

    /// EXPENSIVE PoW verification — recompute the identity hash and check the
    /// target. Call ONLY after `validate_header_cheap` and the height/parent
    /// checks have passed, and pass the current tip so the recompute refuses to
    /// build an epoch cache for an implausibly-far-ahead height.
    ///
    /// Takes `&self` so it can apply THIS node's network activation schedule: on
    /// mainnet a legacy v2 header at height >= 1 must be rejected, which the
    /// network-blind rule would silently accept.
    fn validate_header_pow(&self, header: &BlockHeader, tip_height: u64) -> bool {
        use crate::engine::mining::pow::pow_validator::PowValidator;
        // PoW: recompute hash from header fields, then check target. Without
        // recomputation, an attacker can send a fake hash that meets PoW but
        // doesn't correspond to the header content. Network-aware (activation
        // floor) and tip-bounded (no epoch work for an absurd height).
        let recomputed = PowValidator::recompute_identity_hash_checked(
            header,
            tip_height,
            self.network_mode.as_ref(),
        );
        if recomputed != header.hash {
            return false;
        }
        if header.difficulty > 0
            && !PowValidator::hash_meets_target(&header.hash, header.difficulty)
        {
            return false;
        }
        true
    }

    /// Add a block header to our chain.
    /// First header MUST be genesis (height 0) to establish root of trust.
    pub fn add_header(&mut self, header: BlockHeader) -> bool {
        // ORDERING IS SECURITY (external audit H3): every cheap check runs FIRST,
        // and the expensive identity recompute (which for UmbraHash builds a
        // 16 MiB epoch cache) runs LAST — only once the header has been screened
        // and pinned to tip+1. Previously PoW ran first, so an attacker could
        // force epoch work with a far-height header that the height check would
        // have rejected for free.
        if !Self::validate_header_cheap(&header) {
            return false;
        }

        if self.headers.is_empty() {
            // First header must be genesis — no arbitrary starting point
            if header.height != 0 {
                return false;
            }
            // Verify genesis hash matches the network's known genesis
            if !self.genesis_hash.is_empty() && header.hash != self.genesis_hash {
                return false;
            }
            // Genesis screened → now pay for PoW (tip 0: genesis is epoch 0).
            if !self.validate_header_pow(&header, 0) {
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

        // Fully screened and pinned to tip+1 → only now do the expensive PoW.
        if !self.validate_header_pow(&header, self.best_height) {
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

    /// Verify a transaction exists in a block using Merkle proof.
    /// Finds the header by block_hash (stronger than height alone).
    pub fn verify_tx_inclusion(
        &self,
        tx_hash: &str,
        proof: &MerkleProof,
        block_hash: &str,
    ) -> bool {
        let header = self.headers.iter().find(|h| h.hash == block_hash);
        match header {
            Some(h) => MerkleVerifier::verify(tx_hash.to_string(), proof, h.merkle_root.clone()),
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

    /// Build a header at `height` whose parent is `parent_hash`.
    /// The hash is computed via the real hashing function so that
    /// `validate_header_basic`'s recomputation check passes.
    fn make_header_with_parent(height: u64, parent_hash: &str) -> BlockHeader {
        use crate::engine::mining::algorithms::shadowhash::shadow_hash_raw_full;

        let parents = vec![parent_hash.to_string()];
        let merkle_root = "merkle_root".to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp = now - 60 + height;
        let version = 1u32;
        let nonce = 0u64;
        let extra_nonce = 0u64;
        // Genesis uses difficulty 0; non-genesis uses difficulty 1
        // (easiest target -- any hash passes). validate_header_basic
        // rejects height > 0 with difficulty 0.
        let difficulty = if height == 0 { 0u64 } else { 1u64 };

        let hash = shadow_hash_raw_full(
            version,
            height,
            timestamp,
            nonce,
            extra_nonce,
            difficulty,
            &merkle_root,
            &parents,
            None,
        );

        BlockHeader {
            version,
            hash,
            parents,
            merkle_root,
            timestamp,
            nonce,
            difficulty,
            height,
            blue_score: 0,
            selected_parent: None,
            utxo_commitment: None,
            extra_nonce,
            receipt_root: None,
            state_root: None,
            mix_hash: String::new(),
            prev_state_commitment: None,
        }
    }

    #[test]
    fn add_header_increments_height() {
        // Use an unrecognized network name so genesis_hash is empty,
        // allowing fabricated test headers to pass the genesis check.
        // Real genesis-hash validation is tested separately.
        let mut node = LightNode::new("test_local");
        let null_parent = "0".repeat(64);
        // First header must be genesis (height 0)
        let genesis = make_header_with_parent(0, &null_parent);
        let genesis_hash = genesis.hash.clone();
        assert!(node.add_header(genesis));
        assert_eq!(node.best_height(), 0);
        // Then add height 1, chained to genesis
        assert!(node.add_header(make_header_with_parent(1, &genesis_hash)));
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
