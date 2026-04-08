// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Property-based security tests — Verify security invariants hold for all inputs.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        // ── Atomic Swap Security ────────────────────────────────────
        #[test]
        fn htlc_wrong_secret_never_redeems(
            secret_bytes in prop::collection::vec(0u8..=255, 32),
            wrong_bytes in prop::collection::vec(0u8..=255, 32),
        ) {
            use crate::engine::swap::atomic_swap::AtomicSwap;
            let secret: [u8; 32] = secret_bytes.try_into().unwrap();
            let wrong: [u8; 32] = wrong_bytes.try_into().unwrap();
            let hash = AtomicSwap::hash_secret(&secret);

            if secret != wrong {
                prop_assert!(!AtomicSwap::verify_secret(&wrong, &hash));
            }
        }

        #[test]
        fn htlc_correct_secret_always_redeems(
            secret_bytes in prop::collection::vec(0u8..=255, 32),
        ) {
            use crate::engine::swap::atomic_swap::AtomicSwap;
            let secret: [u8; 32] = secret_bytes.try_into().unwrap();
            let hash = AtomicSwap::hash_secret(&secret);
            prop_assert!(AtomicSwap::verify_secret(&secret, &hash));
        }

        #[test]
        fn htlc_refund_only_after_timeout(
            current in 0u64..1_000_000,
            timeout in 1u64..1_000_000,
        ) {
            use crate::engine::swap::atomic_swap::{AtomicSwap, SwapState};
            let hash = AtomicSwap::hash_secret(&[0u8; 32]);
            let mut htlc = AtomicSwap::initiate(&hash, "a", "b", 100, 0, timeout);

            if current < htlc.timeout_height {
                prop_assert!(!AtomicSwap::refund(&mut htlc, current));
                prop_assert_eq!(htlc.state, SwapState::Initiated);
            }
        }

        // ── DEX Security ────────────────────────────────────────────
        #[test]
        fn dex_no_match_when_prices_dont_cross(
            buy_price in 1u64..1000,
            sell_price in 1u64..1000,
            amount in 1u64..10000,
        ) {
            use crate::engine::dex::order_book::*;
            let mut book = OrderBook::new(TradingPair::new("A", "B"));
            book.place_order(Order {
                id: "s1".into(), owner: "o".into(),
                pair: TradingPair::new("A", "B"),
                side: OrderSide::Sell, order_type: OrderType::Limit,
                price: sell_price, amount, filled: 0,
                status: OrderStatus::Open, timestamp: 0, block_height: 0,
            }).unwrap();
            let trades = book.place_order(Order {
                id: "b1".into(), owner: "o".into(),
                pair: TradingPair::new("A", "B"),
                side: OrderSide::Buy, order_type: OrderType::Limit,
                price: buy_price, amount, filled: 0,
                status: OrderStatus::Open, timestamp: 0, block_height: 0,
            }).unwrap();

            if buy_price < sell_price {
                prop_assert!(trades.is_empty(), "No match when buy < sell price");
            }
        }

        // ── Address Security ────────────────────────────────────────
        #[test]
        fn address_from_different_keys_always_different(
            key1 in prop::collection::vec(0u8..=255, 32),
            key2 in prop::collection::vec(0u8..=255, 32),
        ) {
            use crate::domain::address::address::Address;
            let k1: [u8; 32] = key1.try_into().unwrap();
            let k2: [u8; 32] = key2.try_into().unwrap();
            let a1 = Address::from_public_key(&k1, "mainnet");
            let a2 = Address::from_public_key(&k2, "mainnet");

            if k1 != k2 {
                prop_assert_ne!(a1.value, a2.value);
            } else {
                prop_assert_eq!(a1.value, a2.value);
            }
        }

        #[test]
        fn schnorr_address_always_has_k_prefix(
            key_bytes in prop::collection::vec(0u8..=255, 32),
        ) {
            use crate::domain::address::address::Address;
            let key: [u8; 32] = key_bytes.try_into().unwrap();
            let addr = Address::from_schnorr_key(&key, "mainnet");
            prop_assert!(addr.value.starts_with("SD1k"));
            prop_assert!(addr.is_schnorr());
        }

        #[test]
        fn p2sh_address_always_has_h_prefix(
            script_bytes in prop::collection::vec(0u8..=255, 20..64),
        ) {
            use crate::domain::address::address::Address;
            let addr = Address::from_script_hash(&script_bytes, "mainnet");
            prop_assert!(addr.value.starts_with("SD1h"));
            prop_assert!(addr.is_p2sh());
        }

        // ── Hash Security ───────────────────────────────────────────
        #[test]
        fn shadow_hash_collision_resistant(
            data1 in "[a-z]{1,32}",
            data2 in "[a-z]{1,32}",
        ) {
            use crate::engine::mining::algorithms::shadowhash::shadow_hash_str;
            let h1 = shadow_hash_str(&data1);
            let h2 = shadow_hash_str(&data2);
            if data1 != data2 {
                prop_assert_ne!(h1, h2, "Different inputs must produce different hashes");
            }
        }

        // ── Fee Market Security ─────────────────────────────────────
        #[test]
        fn base_fee_never_zero(
            parent_fee in 1u64..1_000_000,
            gas_used in 0u64..2_000_000,
            gas_limit in 1u64..2_000_000,
        ) {
            use crate::service::mempool::fees::fee_market::FeeMarket;
            let new_fee = FeeMarket::calculate_base_fee(parent_fee, gas_used, gas_limit);
            prop_assert!(new_fee >= 1, "Base fee must never be zero");
        }

        #[test]
        fn effective_fee_capped(
            base in 1u64..1000,
            max_fee in 1u64..1000,
            priority in 0u64..1000,
        ) {
            use crate::service::mempool::fees::fee_market::FeeMarket;
            let eff = FeeMarket::effective_fee(base, max_fee, priority);
            prop_assert!(eff <= max_fee, "Effective fee must not exceed max_fee");
        }
    }
}
