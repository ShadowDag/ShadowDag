// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Property-based tests for consensus-critical invariants.
// Uses proptest to verify that invariants hold across all inputs.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::config::consensus::emission_schedule::EmissionSchedule;
    use crate::engine::dag::core::bps_engine::BpsParams;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn bps_params_always_valid(bps in 0u32..=200) {
            let p = BpsParams::for_bps(bps);
            // BPS clamped to [1, 64]
            prop_assert!(p.bps >= 1 && p.bps <= 64);
            // GHOSTDAG K at least 18
            prop_assert!(p.ghostdag_k >= 18);
            // Max parents at least 8
            prop_assert!(p.max_parents >= 8);
            // Block interval positive
            prop_assert!(p.block_interval_ms >= 1);
            // Max TPS positive
            prop_assert!(p.max_tps >= 10_000);
            // Max block size positive
            prop_assert!(p.max_block_size > 0);
            // Max block txs positive
            prop_assert!(p.max_block_txs > 0);
        }

        #[test]
        fn bps_k_scales_monotonically(a in 1u32..=64, b in 1u32..=64) {
            let pa = BpsParams::for_bps(a);
            let pb = BpsParams::for_bps(b);
            if a < b {
                prop_assert!(pa.ghostdag_k <= pb.ghostdag_k);
                prop_assert!(pa.max_parents <= pb.max_parents);
            }
        }

        #[test]
        fn bps_max_tps_increases_with_bps(a in 1u32..=64, b in 1u32..=64) {
            let pa = BpsParams::for_bps(a);
            let pb = BpsParams::for_bps(b);
            if a < b {
                prop_assert!(pa.max_tps <= pb.max_tps);
            }
        }

        #[test]
        fn emission_never_negative(height in 0u64..500_000_000) {
            let reward = EmissionSchedule::block_reward(height);
            // reward is u64, always >= 0
            let miner = EmissionSchedule::miner_reward(height);
            let dev = EmissionSchedule::developer_reward(height);
            // miner + dev == reward
            prop_assert_eq!(miner + dev, reward);
        }

        #[test]
        fn emission_decreases_over_time(h1 in 0u64..100_000_000, gap in 1u64..100_000_000) {
            let r1 = EmissionSchedule::block_reward(h1);
            let r2 = EmissionSchedule::block_reward(h1.saturating_add(gap));
            // reward should never increase over time
            prop_assert!(r2 <= r1);
        }

        #[test]
        fn difficulty_target_decreases_with_difficulty(d1 in 1u64..1_000_000, d2 in 1u64..1_000_000) {
            use crate::engine::mining::pow::pow_validator::PowValidator;
            let t1 = PowValidator::difficulty_to_target(d1);
            let t2 = PowValidator::difficulty_to_target(d2);
            if d1 < d2 {
                // Higher difficulty = lower (smaller) target
                prop_assert!(t1 >= t2);
            }
        }

        #[test]
        fn shadow_hash_deterministic(
            version in 0u32..10,
            height in 0u64..1000,
            timestamp in 1_000_000u64..2_000_000_000,
            nonce in 0u64..1000,
            difficulty in 1u64..100,
        ) {
            use crate::engine::mining::algorithms::shadowhash::shadow_hash_raw_full;
            let h1 = shadow_hash_raw_full(version, height, timestamp, nonce, 0, difficulty, "merkle", &[]);
            let h2 = shadow_hash_raw_full(version, height, timestamp, nonce, 0, difficulty, "merkle", &[]);
            prop_assert_eq!(h1.len(), 64);
            prop_assert_eq!(h1, h2);
        }
    }
}
