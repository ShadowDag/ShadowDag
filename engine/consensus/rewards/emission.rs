// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::consensus::emission_schedule::EmissionSchedule;

pub struct Emission;

impl Emission {
    /// Get block reward at height, capped by MAX_SUPPLY.
    /// The raw EmissionSchedule gives the mathematical reward.
    /// This function additionally checks if total emission has reached MAX_SUPPLY.
    #[inline(always)]
    pub fn block_reward(height: u64) -> u64 {
        let reward = EmissionSchedule::block_reward(height);
        if reward == 0 {
            return 0;
        }

        // MAX_SUPPLY enforcement
        let max_supply = crate::config::consensus::consensus_params::ConsensusParams::MAX_SUPPLY;
        let emitted = if height == 0 {
            0
        } else {
            EmissionSchedule::total_emitted(height - 1)
        };
        if emitted >= max_supply {
            return 0; // Cap reached
        }
        let remaining = max_supply - emitted;
        reward.min(remaining)
    }

    /// Calculate total supply emitted up to a given height.
    /// Uses the EmissionSchedule's efficient era-based calculation.
    /// Does NOT precompute a giant Vec — uses O(1) math per era.
    pub fn total_supply(height: u64) -> u64 {
        let raw = EmissionSchedule::total_emitted(height);
        let max_supply = crate::config::consensus::consensus_params::ConsensusParams::MAX_SUPPLY;
        raw.min(max_supply)
    }
}
