// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Edge case tests — boundary conditions that could cause crashes or bugs.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    // ── u64 Boundary Tests ──────────────────────────────────────────

    #[test]
    fn emission_at_max_height() {
        use crate::config::consensus::emission_schedule::EmissionSchedule;
        let reward = EmissionSchedule::block_reward(u64::MAX);
        assert_eq!(reward, 0, "Reward at max height must be 0");
    }

    #[test]
    fn emission_at_zero_height() {
        use crate::config::consensus::emission_schedule::EmissionSchedule;
        let reward = EmissionSchedule::block_reward(0);
        assert_eq!(reward, 1_000_000_000, "Genesis reward = 10 SDAG");
    }

    #[test]
    fn difficulty_adjust_with_zero_time() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        let result = Difficulty::adjust(1000, 0, 100);
        assert!(result >= Difficulty::MIN_DIFFICULTY);
        assert!(result <= Difficulty::MAX_DIFFICULTY);
    }

    #[test]
    fn difficulty_adjust_with_zero_blocks() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        let result = Difficulty::adjust(1000, 1000, 0);
        assert!(result >= Difficulty::MIN_DIFFICULTY);
    }

    #[test]
    fn difficulty_adjust_with_max_values() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        let result = Difficulty::adjust(u64::MAX / 2, u64::MAX, u64::MAX);
        assert!(result >= Difficulty::MIN_DIFFICULTY);
        assert!(result <= Difficulty::MAX_DIFFICULTY);
    }

    #[test]
    fn difficulty_from_target_zero() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        let d = Difficulty::from_target(0);
        assert_eq!(d, Difficulty::MAX_DIFFICULTY);
    }

    #[test]
    fn difficulty_to_target_min() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        let t = Difficulty::to_target(1);
        assert!(t > 0);
    }

    // ── Hash Edge Cases ─────────────────────────────────────────────

    #[test]
    fn hash_meets_target_empty_hash() {
        use crate::engine::mining::pow::pow_validator::PowValidator;
        assert!(!PowValidator::hash_meets_target("", 1));
    }

    #[test]
    fn hash_meets_target_short_hash() {
        use crate::engine::mining::pow::pow_validator::PowValidator;
        assert!(!PowValidator::hash_meets_target("abc", 1));
    }

    #[test]
    fn hash_meets_target_invalid_hex() {
        use crate::engine::mining::pow::pow_validator::PowValidator;
        let invalid = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(!PowValidator::hash_meets_target(invalid, 1));
    }

    #[test]
    fn hash_meets_target_max_difficulty() {
        use crate::engine::mining::pow::pow_validator::PowValidator;
        let zeros = "0".repeat(64);
        assert!(PowValidator::hash_meets_target(&zeros, u64::MAX));
    }

    // ── BPS Edge Cases ──────────────────────────────────────────────

    #[test]
    fn bps_zero_clamped_to_one() {
        use crate::engine::dag::core::bps_engine::BpsParams;
        let p = BpsParams::for_bps(0);
        assert_eq!(p.bps, 1);
    }

    #[test]
    fn bps_max_clamped_to_64() {
        use crate::engine::dag::core::bps_engine::BpsParams;
        let p = BpsParams::for_bps(1000);
        assert_eq!(p.bps, 64);
    }

    #[test]
    fn bps_interval_never_zero() {
        use crate::engine::dag::core::bps_engine::BpsParams;
        for bps in 1..=64 {
            let p = BpsParams::for_bps(bps);
            assert!(p.block_interval_ms >= 1, "BPS {} has 0 interval", bps);
        }
    }

    // ── Address Edge Cases ──────────────────────────────────────────

    #[test]
    fn address_from_zero_key() {
        use crate::domain::address::address::Address;
        let addr = Address::from_public_key(&[0u8; 32], "mainnet");
        assert!(addr.is_valid());
    }

    #[test]
    fn address_from_max_key() {
        use crate::domain::address::address::Address;
        let addr = Address::from_public_key(&[0xFF; 32], "mainnet");
        assert!(addr.is_valid());
    }

    #[test]
    fn address_empty_is_invalid() {
        use crate::domain::address::address::Address;
        let addr = Address::new(String::new());
        assert!(!addr.is_valid());
    }

    #[test]
    fn schnorr_and_standard_differ() {
        use crate::domain::address::address::Address;
        let key = [0x42u8; 32];
        let standard = Address::from_public_key(&key, "mainnet");
        let schnorr = Address::from_schnorr_key(&key, "mainnet");
        assert_ne!(standard.value, schnorr.value, "Different address types must differ");
    }

    // ── Atomic Swap Edge Cases ──────────────────────────────────────

    #[test]
    fn htlc_zero_amount() {
        use crate::engine::swap::atomic_swap::AtomicSwap;
        let hash = AtomicSwap::hash_secret(&[0u8; 32]);
        let htlc = AtomicSwap::initiate(&hash, "a", "b", 0, 0, 86400);
        assert_eq!(htlc.amount, 0);
    }

    #[test]
    fn htlc_max_timeout() {
        use crate::engine::swap::atomic_swap::AtomicSwap;
        let hash = AtomicSwap::hash_secret(&[1u8; 32]);
        let htlc = AtomicSwap::initiate(&hash, "a", "b", 100, 0, u64::MAX / 2);
        assert!(htlc.timeout_height > 0);
    }

    // ── DEX Edge Cases ──────────────────────────────────────────────

    #[test]
    fn dex_empty_order_book() {
        use crate::engine::dex::order_book::*;
        let book = OrderBook::new(TradingPair::new("A", "B"));
        assert_eq!(book.best_bid(), None);
        assert_eq!(book.best_ask(), None);
        assert_eq!(book.spread(), None);
        assert_eq!(book.depth(), (0, 0));
    }

    #[test]
    fn dex_zero_amount_order() {
        use crate::engine::dex::order_book::*;
        let mut book = OrderBook::new(TradingPair::new("A", "B"));
        let order = Order {
            id: "z1".into(), owner: "o".into(),
            pair: TradingPair::new("A", "B"),
            side: OrderSide::Buy, order_type: OrderType::Limit,
            price: 100, amount: 0, filled: 0,
            status: OrderStatus::Open, timestamp: 0, block_height: 0,
        };
        let trades = book.place_order(order).unwrap();
        assert!(trades.is_empty());
    }

    // ── Merkle Edge Cases ───────────────────────────────────────────

    #[test]
    fn merkle_single_element() {
        use crate::domain::block::merkle_tree::MerkleTree;
        let root = MerkleTree::calculate_root(vec!["aa".repeat(32)]);
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn merkle_two_identical_elements() {
        use crate::domain::block::merkle_tree::MerkleTree;
        let hash = "bb".repeat(32);
        let root = MerkleTree::calculate_root(vec![hash.clone(), hash]);
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn merkle_proof_index_zero() {
        use crate::domain::block::merkle_tree::MerkleTree;
        let hashes = vec!["aa".repeat(32), "bb".repeat(32)];
        let root = MerkleTree::calculate_root(hashes.clone());
        let proof = MerkleTree::generate_proof(&hashes, 0).unwrap();
        assert!(MerkleTree::verify_proof(&hashes[0], &proof, &root));
    }

    #[test]
    fn merkle_proof_last_index() {
        use crate::domain::block::merkle_tree::MerkleTree;
        let hashes = vec!["aa".repeat(32), "bb".repeat(32), "cc".repeat(32)];
        let root = MerkleTree::calculate_root(hashes.clone());
        let proof = MerkleTree::generate_proof(&hashes, 2).unwrap();
        assert!(MerkleTree::verify_proof(&hashes[2], &proof, &root));
    }

    // ── Fee Market Edge Cases ───────────────────────────────────────

    #[test]
    fn base_fee_with_zero_gas_limit() {
        use crate::service::mempool::fees::fee_market::FeeMarket;
        let fee = FeeMarket::calculate_base_fee(100, 0, 0);
        assert!(fee >= 1, "Base fee must never be zero");
    }

    #[test]
    fn base_fee_with_max_gas() {
        use crate::service::mempool::fees::fee_market::FeeMarket;
        let fee = FeeMarket::calculate_base_fee(100, u64::MAX / 2, u64::MAX / 2);
        assert!(fee >= 1);
    }

    // ── Blue Work Edge Cases ────────────────────────────────────────

    #[test]
    fn blue_work_zero_difficulty() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        let work = Difficulty::blue_work(0);
        assert_eq!(work, 0);
    }

    #[test]
    fn blue_work_accumulate_from_zero() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        let work = Difficulty::accumulate_blue_work(0, 100);
        assert_eq!(work, 100);
    }

    #[test]
    fn blue_work_accumulate_saturates() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        let work = Difficulty::accumulate_blue_work(u128::MAX - 10, u64::MAX);
        assert_eq!(work, u128::MAX); // saturating_add
    }

    // ── Past Median Time Edge Cases ─────────────────────────────────

    #[test]
    fn past_median_time_empty() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        assert_eq!(Difficulty::past_median_time(&[]), 0);
    }

    #[test]
    fn past_median_time_single() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        assert_eq!(Difficulty::past_median_time(&[42]), 42);
    }

    #[test]
    fn past_median_time_even_count() {
        use crate::engine::consensus::difficulty::difficulty::Difficulty;
        let pmt = Difficulty::past_median_time(&[10, 20, 30, 40]);
        assert!(pmt >= 10 && pmt <= 40);
    }
}
