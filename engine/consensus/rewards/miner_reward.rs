// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::engine::consensus::rewards::reward::Reward;

#[inline(always)]
#[must_use]
pub fn miner_reward(block_reward: u64) -> u64 {
    // Deterministic, branch-free, fast computation
    Reward::miner_portion(block_reward)
}
