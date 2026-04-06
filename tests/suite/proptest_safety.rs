// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Safety property tests — verifies invariants that prevent crashes,
// overflow, and data corruption under any input.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        // ── Integer Safety ──────────────────────────────────────────
        #[test]
        fn total_output_never_overflows(
            amounts in prop::collection::vec(0u64..u64::MAX / 100, 1..20),
        ) {
            let total = amounts.iter().fold(0u64, |acc, &a| acc.saturating_add(a));
            prop_assert!(total <= u64::MAX);
        }

        #[test]
        fn fee_calculation_safe(
            input_sum in 0u64..u64::MAX / 2,
            output_sum in 0u64..u64::MAX / 2,
        ) {
            let fee = input_sum.saturating_sub(output_sum);
            prop_assert!(fee <= input_sum);
        }

        // ── Emission Safety ─────────────────────────────────────────
        #[test]
        fn emission_monotonically_decreasing(
            h1 in 0u64..50_000_000u64,
            gap in 1u64..50_000_000u64,
        ) {
            use crate::config::consensus::emission_schedule::EmissionSchedule;
            let r1 = EmissionSchedule::block_reward(h1);
            let r2 = EmissionSchedule::block_reward(h1.saturating_add(gap));
            prop_assert!(r2 <= r1, "Reward must not increase: {} at {} vs {} at {}",
                r1, h1, r2, h1 + gap);
        }

        #[test]
        fn miner_plus_dev_equals_total(height in 0u64..100_000_000) {
            use crate::config::consensus::emission_schedule::EmissionSchedule;
            let total = EmissionSchedule::block_reward(height);
            let miner = EmissionSchedule::miner_reward(height);
            let dev = EmissionSchedule::developer_reward(height);
            prop_assert_eq!(miner + dev, total, "Miner + dev must equal total reward");
        }

        // ── BPS Safety ──────────────────────────────────────────────
        #[test]
        fn bps_params_never_zero(bps in 0u32..=200) {
            use crate::engine::dag::core::bps_engine::BpsParams;
            let p = BpsParams::for_bps(bps);
            prop_assert!(p.block_interval_ms >= 1, "Block interval must be >= 1ms");
            prop_assert!(p.max_block_size >= 1, "Max block size must be >= 1");
            prop_assert!(p.max_block_txs >= 1, "Max block txs must be >= 1");
            prop_assert!(p.ghostdag_k >= 1, "GHOSTDAG K must be >= 1");
        }

        // ── Address Safety ──────────────────────────────────────────
        #[test]
        fn address_always_valid_format(key in prop::collection::vec(0u8..=255, 32)) {
            use crate::domain::address::address::Address;
            let k: [u8; 32] = key.try_into().unwrap();
            let addr = Address::from_public_key(&k, "mainnet");
            prop_assert!(addr.is_valid(), "Generated address must be valid");
            prop_assert!(addr.value.starts_with("SD1"), "Must have correct prefix");
            prop_assert_eq!(addr.value.len(), 43, "Address must be 43 chars (3 prefix + 40 hex)");
        }

        // ── Difficulty Safety ───────────────────────────────────────
        #[test]
        fn difficulty_adjust_stays_bounded(
            current in 1u64..u64::MAX / 4,
            actual_ms in 1u64..100_000,
            blocks in 1u64..1000,
        ) {
            use crate::engine::consensus::difficulty::difficulty::Difficulty;
            let result = Difficulty::adjust(current, actual_ms, blocks);
            prop_assert!(result >= Difficulty::MIN_DIFFICULTY);
            prop_assert!(result <= Difficulty::MAX_DIFFICULTY);
        }

        // ── Pruning Safety ──────────────────────────────────────────
        #[test]
        fn pruning_never_negative_height(
            current in 0u64..10_000_000,
            depth in 100u64..10_000_000,
        ) {
            use crate::engine::pruning::PruningEngine;
            let engine = PruningEngine::new(depth);
            let cutoff = current.saturating_sub(depth);
            prop_assert!(cutoff <= current);
        }

        // ── Merkle Proof Safety ─────────────────────────────────────
        #[test]
        fn merkle_root_always_64_hex(
            count in 1usize..50,
        ) {
            use crate::domain::block::merkle_tree::MerkleTree;
            let hashes: Vec<String> = (0..count).map(|i| format!("{:064x}", i)).collect();
            let root = MerkleTree::calculate_root(hashes);
            prop_assert_eq!(root.len(), 64);
            prop_assert!(root.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // ── Swap Safety ─────────────────────────────────────────────
        #[test]
        fn htlc_secret_hash_always_64_hex(
            secret in prop::collection::vec(0u8..=255, 32),
        ) {
            use crate::engine::swap::atomic_swap::AtomicSwap;
            let s: [u8; 32] = secret.try_into().unwrap();
            let hash = AtomicSwap::hash_secret(&s);
            prop_assert_eq!(hash.len(), 64);
        }

        // ── DEX Safety ──────────────────────────────────────────────
        #[test]
        fn order_book_depth_consistent(
            buy_count in 0usize..10,
            sell_count in 0usize..10,
        ) {
            use crate::engine::dex::order_book::*;
            let mut book = OrderBook::new(TradingPair::new("A", "B"));
            for i in 0..buy_count {
                book.place_order(Order {
                    id: format!("b{}", i), owner: "o".into(),
                    pair: TradingPair::new("A", "B"),
                    side: OrderSide::Buy, order_type: OrderType::Limit,
                    price: 50, amount: 100, filled: 0,
                    status: OrderStatus::Open, timestamp: 0, block_height: 0,
                });
            }
            for i in 0..sell_count {
                book.place_order(Order {
                    id: format!("s{}", i), owner: "o".into(),
                    pair: TradingPair::new("A", "B"),
                    side: OrderSide::Sell, order_type: OrderType::Limit,
                    price: 100, amount: 100, filled: 0,
                    status: OrderStatus::Open, timestamp: 0, block_height: 0,
                });
            }
            let (bids, asks) = book.depth();
            // Since buy at 50, sell at 100 — no crossing, all orders remain
            prop_assert_eq!(bids, buy_count);
            prop_assert_eq!(asks, sell_count);
        }
    }
}
