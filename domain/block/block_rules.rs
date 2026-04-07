// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Block Rules — Full block validation including header integrity.
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block::Block;
use crate::domain::block::merkle_tree::MerkleTree;
use crate::domain::traits::pow_checker::PowChecker;
use crate::engine::mining::algorithms::shadowhash::shadow_hash_raw_full;

/// Maximum future timestamp drift (consensus: 120 seconds).
/// Canonical value defined in block_validator::MAX_FUTURE_SECS.
const MAX_FUTURE_TIME_SECS: u64 = 120;

pub struct BlockRules;

impl BlockRules {
    /// Quick validation (header only, no UTXO check)
    pub fn validate_header_only(block: &Block, pow: &dyn PowChecker) -> bool {
        if block.header.hash.is_empty() { return false; }
        if block.header.difficulty == 0 { return false; }
        if block.header.height > 0 && block.header.parents.is_empty() { return false; }
        // Prevent DoS: reject blocks with too many parents (GHOSTDAG = O(parents²))
        if block.header.parents.len() > crate::config::consensus::consensus_params::ConsensusParams::MAX_PARENTS {
            return false;
        }
        // Reject blocks with timestamps too far in the future
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if block.header.timestamp > now + MAX_FUTURE_TIME_SECS {
            return false;
        }

        // Recompute hash from header fields and verify it matches claimed hash
        let computed = shadow_hash_raw_full(
            block.header.version,
            block.header.height,
            block.header.timestamp,
            block.header.nonce,
            block.header.extra_nonce,
            block.header.difficulty,
            &block.header.merkle_root,
            &block.header.parents,
        );
        if computed != block.header.hash {
            return false; // Hash doesn't match header content
        }

        // Verify merkle root matches the block body transactions
        let computed_merkle = MerkleTree::build(
            &block.body.transactions,
            block.header.height,
            &block.header.parents,
        );
        if computed_merkle != block.header.merkle_root {
            return false;
        }

        pow.hash_meets_target(&block.header.hash, block.header.difficulty)
    }
}
