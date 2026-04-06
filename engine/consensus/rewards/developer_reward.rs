// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::engine::consensus::rewards::reward::Reward;

#[inline(always)]
#[must_use]
pub fn developer_reward(block_reward: u64) -> u64 {
    // Deterministic, branch-free fast path
    Reward::developer_portion(block_reward)
}