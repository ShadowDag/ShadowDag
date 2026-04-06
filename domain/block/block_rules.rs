// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Block Rules — Full block validation including header integrity.
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block::Block;
use crate::domain::traits::pow_checker::PowChecker;

/// Maximum future timestamp drift (consensus: 120 seconds).
/// Canonical value defined in block_validator::MAX_FUTURE_SECS.
const MAX_FUTURE_TIME_SECS: u64 = 120;

/// Maximum block size in bytes
const MAX_BLOCK_SIZE: usize = 2 * 1024 * 1024;

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
        pow.hash_meets_target(&block.header.hash, block.header.difficulty)
    }
}
