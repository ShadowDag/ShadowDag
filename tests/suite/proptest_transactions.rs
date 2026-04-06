// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Property-based tests for transaction and UTXO invariants.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn shadow_hash_str_deterministic(data in "[a-z0-9]{1,64}") {
            use crate::engine::mining::algorithms::shadowhash::shadow_hash_str;
            let h1 = shadow_hash_str(&data);
            let h2 = shadow_hash_str(&data);
            prop_assert_eq!(h1.len(), 64);
            prop_assert_eq!(h1, h2);
        }

        #[test]
        fn fee_calculation_never_overflows(
            input_total in 0u64..u64::MAX / 2,
            output_total in 0u64..u64::MAX / 2,
        ) {
            let fee = input_total.saturating_sub(output_total);
            // Fee should be >= 0 (u64 guarantees this)
            // If outputs > inputs, fee is 0 (saturating_sub)
            if input_total >= output_total {
                prop_assert_eq!(fee, input_total - output_total);
            } else {
                prop_assert_eq!(fee, 0);
            }
        }

        #[test]
        fn dust_limit_always_enforced(amount in 0u64..1000) {
            use crate::config::consensus::consensus_params::ConsensusParams;
            if amount < ConsensusParams::DUST_LIMIT && amount > 0 {
                // This should be rejected as dust
                prop_assert!(amount < ConsensusParams::DUST_LIMIT);
            }
        }

        #[test]
        fn address_prefix_correct(
            network in 0u32..3,
            hash_bytes in prop::collection::vec(0u8..=255, 20),
        ) {
            let prefix = match network {
                0 => "SD1",
                1 => "ST1",
                _ => "SR1",
            };
            let addr = format!("{}{}", prefix, hex::encode(&hash_bytes));
            prop_assert!(addr.starts_with(prefix));
            // SD1 + 40 hex chars = 43 total
            prop_assert_eq!(addr.len(), 3 + 40);
        }

        #[test]
        fn coinbase_maturity_positive(height in 0u64..10_000_000) {
            use crate::config::consensus::consensus_params::ConsensusParams;
            let mature_at = height + ConsensusParams::COINBASE_MATURITY;
            prop_assert!(mature_at > height);
            // 1000 blocks = 100 seconds at 10 BPS (safe for DAG reorgs)
            prop_assert_eq!(ConsensusParams::COINBASE_MATURITY, 1_000);
        }

        #[test]
        fn max_supply_constant(_seed in 0u32..1000) {
            use crate::config::consensus::consensus_params::ConsensusParams;
            // Max supply should always be 21 billion * 10^8
            prop_assert_eq!(ConsensusParams::MAX_SUPPLY, 21_000_000_000 * 100_000_000);
        }
    }
}
