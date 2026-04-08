// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod pow_tests {
    use crate::engine::mining::algorithms::shadowhash::{
        shadow_hash_raw, shadow_hash_str, meets_difficulty,
    };
    use crate::engine::mining::miner::miner::Miner;

    #[test]
    fn hash_is_64_chars() {
        let h = shadow_hash_raw(1, 0, 1735689600, 0, 4, "merkle", &[]);
        assert_eq!(h.len(), 64, "SHA-256/SHA3-256 hash must be 64 hex chars");
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = shadow_hash_raw(1, 1, 1735689600, 42, 4, "some_merkle", &[]);
        let h2 = shadow_hash_raw(1, 1, 1735689600, 42, 4, "some_merkle", &[]);
        assert_eq!(h1, h2, "Same inputs must produce same PoW hash");
    }

    #[test]
    fn different_nonce_different_hash() {
        let h1 = shadow_hash_raw(1, 1, 1735689600, 1, 4, "merkle", &[]);
        let h2 = shadow_hash_raw(1, 1, 1735689600, 2, 4, "merkle", &[]);
        assert_ne!(h1, h2, "Different nonce must yield different hash");
    }

    #[test]
    fn different_height_different_hash() {
        let h1 = shadow_hash_raw(1, 1, 1735689600, 0, 4, "merkle", &[]);
        let h2 = shadow_hash_raw(1, 2, 1735689600, 0, 4, "merkle", &[]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn meets_difficulty_one() {
        // difficulty=1 → target = MAX → any valid 64-char hash passes
        let easy_hash = "0".repeat(64);
        assert!(meets_difficulty(&easy_hash, 1));
    }

    #[test]
    fn meets_difficulty_high_rejects_large_hash() {
        // difficulty very high → target very small → large hash fails
        let large_hash = "f".repeat(64);
        assert!(!meets_difficulty(&large_hash, 1000));
    }

    #[test]
    fn meets_difficulty_zero_returns_false() {
        // difficulty=0 is only for genesis, meets_difficulty returns false as safety
        let hash = "0".repeat(64);
        assert!(!meets_difficulty(&hash, 0));
    }

    #[test]
    fn shadow_hash_str_is_64_chars() {
        let h = shadow_hash_str("hello world");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn shadow_hash_str_deterministic() {
        let h1 = shadow_hash_str("test data");
        let h2 = shadow_hash_str("test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn coinbase_hash_deterministic() {
        let h1 = Miner::coinbase_hash("shadow1miner", 1735689600, 5, 950, 50, 0);
        let h2 = Miner::coinbase_hash("shadow1miner", 1735689600, 5, 950, 50, 0);
        assert_eq!(h1, h2);
    }

    #[test]
    fn coinbase_hash_unique_per_height() {
        let h1 = Miner::coinbase_hash("shadow1miner", 1735689600, 5, 950, 50, 0);
        let h2 = Miner::coinbase_hash("shadow1miner", 1735689600, 6, 950, 50, 0);
        assert_ne!(h1, h2);
    }

    #[test]
    fn coinbase_hash_unique_per_miner() {
        let h1 = Miner::coinbase_hash("shadow1miner_a", 1735689600, 5, 950, 50, 0);
        let h2 = Miner::coinbase_hash("shadow1miner_b", 1735689600, 5, 950, 50, 0);
        assert_ne!(h1, h2);
    }
}

#[cfg(test)]
mod genesis_tests_comprehensive {
    use crate::config::genesis::genesis::{
        create_genesis_block, verify_genesis,
        compute_merkle_root, GENESIS_TIMESTAMP,
        GENESIS_REWARD, GENESIS_HEIGHT,
    };

    #[test]
    fn genesis_is_deterministic() {
        let g1 = create_genesis_block();
        let g2 = create_genesis_block();
        assert_eq!(g1.header.hash, g2.header.hash);
    }

    #[test]
    fn genesis_height_is_zero() {
        let g = create_genesis_block();
        assert_eq!(g.header.height, GENESIS_HEIGHT);
    }

    #[test]
    fn genesis_has_no_parents() {
        let g = create_genesis_block();
        assert!(g.header.parents.is_empty());
    }

    #[test]
    fn genesis_has_coinbase() {
        let g = create_genesis_block();
        assert_eq!(g.body.transactions.len(), 1);
        assert!(g.body.transactions[0].is_coinbase());
    }

    #[test]
    fn genesis_coinbase_total_reward() {
        let g = create_genesis_block();
        let total: u64 = g.body.transactions[0].outputs.iter().map(|o| o.amount).sum();
        assert_eq!(total, GENESIS_REWARD);
    }

    #[test]
    fn genesis_verify_passes() {
        let g = create_genesis_block();
        assert!(verify_genesis(&g));
    }

    #[test]
    fn genesis_verify_fails_tampered_hash() {
        let mut g = create_genesis_block();
        g.header.hash = "000000tampered".to_string();
        assert!(!verify_genesis(&g));
    }

    #[test]
    fn genesis_verify_fails_with_parents() {
        let mut g = create_genesis_block();
        g.header.parents = vec!["some_parent".to_string()];
        assert!(!verify_genesis(&g));
    }

    #[test]
    fn genesis_hash_is_64_chars() {
        let g = create_genesis_block();
        assert_eq!(g.header.hash.len(), 64);
    }

    #[test]
    fn genesis_timestamp_correct() {
        let g = create_genesis_block();
        assert_eq!(g.header.timestamp, GENESIS_TIMESTAMP);
    }

    #[test]
    fn merkle_root_is_deterministic() {
        let r1 = compute_merkle_root(&["abc".to_string(), "def".to_string()]);
        let r2 = compute_merkle_root(&["abc".to_string(), "def".to_string()]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_empty_returns_zeroes() {
        let r = compute_merkle_root(&[]);
        assert_eq!(r.len(), 64);
    }

    #[test]
    fn merkle_root_single_element() {
        // Must pass a valid 64-char hex hash (like a real tx hash)
        let hash = "a".repeat(64);
        let r = compute_merkle_root(&[hash]);
        assert!(!r.is_empty());
        assert_eq!(r.len(), 64);
    }
}
