// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod pow_tests {
    use crate::config::consensus::consensus_params::ConsensusParams;
    use crate::config::consensus::emission_schedule::EmissionSchedule;
    use crate::config::genesis::genesis::{
        GENESIS_MINER_ADDRESS, OWNER_REWARD_ADDRESS, TESTNET_DEV_ADDRESS, TESTNET_MINER_ADDRESS,
    };
    use crate::domain::block::block::Block;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;
    use crate::engine::mining::algorithms::shadowhash::{
        meets_difficulty, shadow_hash_raw_full, shadow_hash_str,
    };
    use crate::engine::mining::miner::miner::Miner;

    #[test]
    fn hash_is_64_chars() {
        let h = shadow_hash_raw_full(1, 0, 1735689600, 0, 0, 4, "merkle", &[]);
        assert_eq!(h.len(), 64, "SHA-256/SHA3-256 hash must be 64 hex chars");
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = shadow_hash_raw_full(1, 1, 1735689600, 42, 0, 4, "some_merkle", &[]);
        let h2 = shadow_hash_raw_full(1, 1, 1735689600, 42, 0, 4, "some_merkle", &[]);
        assert_eq!(h1, h2, "Same inputs must produce same PoW hash");
    }

    #[test]
    fn different_nonce_different_hash() {
        let h1 = shadow_hash_raw_full(1, 1, 1735689600, 1, 0, 4, "merkle", &[]);
        let h2 = shadow_hash_raw_full(1, 1, 1735689600, 2, 0, 4, "merkle", &[]);
        assert_ne!(h1, h2, "Different nonce must yield different hash");
    }

    #[test]
    fn different_height_different_hash() {
        let h1 = shadow_hash_raw_full(1, 1, 1735689600, 0, 0, 4, "merkle", &[]);
        let h2 = shadow_hash_raw_full(1, 2, 1735689600, 0, 0, 4, "merkle", &[]);
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

    #[test]
    fn mining_ten_years_daily_checkpoints_pow_and_rewards() {
        let miner = Miner::new(1, "shadow1devreward".to_string());
        let bps = ConsensusParams::BLOCKS_PER_SECOND;
        let one_day_secs: u64 = 24 * 60 * 60;
        let total_days: u64 = 10 * 365;
        let mut checkpoints: Vec<u64> = (0..=total_days).step_by(7).collect();
        if checkpoints.last().copied() != Some(total_days) {
            checkpoints.push(total_days);
        }
        let mut prev_hash = String::new();
        let mut prev_reward = u64::MAX;

        for day in checkpoints {
            let height = day.saturating_mul(one_day_secs).saturating_mul(bps);
            let timestamp = 1_735_689_600u64.saturating_add(day.saturating_mul(one_day_secs));

            let coinbase = miner.create_coinbase("shadow1miner".to_string(), timestamp, height);
            assert_eq!(
                coinbase.outputs.len(),
                2,
                "coinbase must have miner+dev outputs"
            );

            let expected_total = EmissionSchedule::block_reward(height);
            let expected_miner = EmissionSchedule::miner_reward(height);
            let expected_dev = EmissionSchedule::developer_reward(height);

            assert_eq!(
                coinbase.outputs[0].amount, expected_miner,
                "miner output mismatch at day {}",
                day
            );
            assert_eq!(
                coinbase.outputs[1].amount, expected_dev,
                "developer output mismatch at day {}",
                day
            );
            assert_eq!(
                coinbase.outputs[0]
                    .amount
                    .saturating_add(coinbase.outputs[1].amount),
                expected_total,
                "coinbase total mismatch at day {}",
                day
            );

            assert!(
                expected_total <= prev_reward,
                "emission must be non-increasing: day {} reward {} > prev {}",
                day,
                expected_total,
                prev_reward
            );
            prev_reward = expected_total;

            let parents = if day == 0 {
                Vec::new()
            } else {
                vec![prev_hash.clone()]
            };
            let block = Block {
                header: BlockHeader::new_with_defaults(
                    1,
                    String::new(),
                    parents,
                    coinbase.hash.clone(),
                    timestamp,
                    0,
                    1,
                    height,
                ),
                body: BlockBody {
                    transactions: vec![coinbase],
                },
            };

            let mined = miner.mine_block(block);
            assert!(
                !mined.header.hash.is_empty(),
                "mining failed at day {}",
                day
            );
            assert!(Miner::verify_pow(&mined), "invalid PoW at day {}", day);
            prev_hash = mined.header.hash;
        }
    }

    #[test]
    fn mining_five_years_testnet_weekly_checkpoints_pow_rewards_and_addresses() {
        let miner = Miner::new(1, TESTNET_DEV_ADDRESS.to_string());
        let bps = ConsensusParams::BLOCKS_PER_SECOND;
        let one_day_secs: u64 = 24 * 60 * 60;
        let total_days: u64 = 5 * 365;
        let mut checkpoints: Vec<u64> = (0..=total_days).step_by(7).collect();
        if checkpoints.last().copied() != Some(total_days) {
            checkpoints.push(total_days);
        }

        let mut prev_hash = String::new();
        let mut prev_reward = u64::MAX;

        for day in checkpoints {
            let height = day.saturating_mul(one_day_secs).saturating_mul(bps);
            let timestamp = 1_735_689_600u64.saturating_add(day.saturating_mul(one_day_secs));

            let coinbase = miner.create_coinbase(TESTNET_MINER_ADDRESS.to_string(), timestamp, height);
            assert_eq!(
                coinbase.outputs.len(),
                2,
                "testnet coinbase must have miner + dev outputs"
            );
            assert_eq!(
                coinbase.outputs[0].address,
                TESTNET_MINER_ADDRESS,
                "testnet miner output address mismatch at day {}",
                day
            );
            assert_eq!(
                coinbase.outputs[1].address,
                TESTNET_DEV_ADDRESS,
                "testnet dev output address mismatch at day {}",
                day
            );

            let expected_total = EmissionSchedule::block_reward(height);
            let expected_miner = EmissionSchedule::miner_reward(height);
            let expected_dev = EmissionSchedule::developer_reward(height);
            assert_eq!(
                coinbase.outputs[0].amount,
                expected_miner,
                "testnet miner reward mismatch at day {}",
                day
            );
            assert_eq!(
                coinbase.outputs[1].amount,
                expected_dev,
                "testnet dev reward mismatch at day {}",
                day
            );
            assert_eq!(
                coinbase.outputs[0]
                    .amount
                    .saturating_add(coinbase.outputs[1].amount),
                expected_total,
                "testnet total reward mismatch at day {}",
                day
            );
            assert!(
                expected_total <= prev_reward,
                "testnet emission must be non-increasing: day {} reward {} > prev {}",
                day,
                expected_total,
                prev_reward
            );
            prev_reward = expected_total;

            let parents = if day == 0 {
                Vec::new()
            } else {
                vec![prev_hash.clone()]
            };
            let block = Block {
                header: BlockHeader::new_with_defaults(
                    1,
                    String::new(),
                    parents,
                    coinbase.hash.clone(),
                    timestamp,
                    0,
                    1,
                    height,
                ),
                body: BlockBody {
                    transactions: vec![coinbase],
                },
            };

            let mined = miner.mine_block(block);
            assert!(
                !mined.header.hash.is_empty(),
                "testnet mining failed at day {}",
                day
            );
            assert!(
                Miner::verify_pow(&mined),
                "invalid testnet PoW at day {}",
                day
            );
            prev_hash = mined.header.hash;
        }
    }

    #[test]
    fn mining_five_years_mainnet_weekly_checkpoints_pow_rewards_and_addresses() {
        let miner = Miner::new(1, OWNER_REWARD_ADDRESS.to_string());
        let bps = ConsensusParams::BLOCKS_PER_SECOND;
        let one_day_secs: u64 = 24 * 60 * 60;
        let total_days: u64 = 5 * 365;
        let mut checkpoints: Vec<u64> = (0..=total_days).step_by(7).collect();
        if checkpoints.last().copied() != Some(total_days) {
            checkpoints.push(total_days);
        }

        let mut prev_hash = String::new();
        let mut prev_reward = u64::MAX;

        for day in checkpoints {
            let height = day.saturating_mul(one_day_secs).saturating_mul(bps);
            let timestamp = 1_735_689_600u64.saturating_add(day.saturating_mul(one_day_secs));

            let coinbase = miner.create_coinbase(GENESIS_MINER_ADDRESS.to_string(), timestamp, height);
            assert_eq!(
                coinbase.outputs.len(),
                2,
                "mainnet coinbase must have miner + dev outputs"
            );
            assert_eq!(
                coinbase.outputs[0].address,
                GENESIS_MINER_ADDRESS,
                "mainnet miner output address mismatch at day {}",
                day
            );
            assert_eq!(
                coinbase.outputs[1].address,
                OWNER_REWARD_ADDRESS,
                "mainnet dev output address mismatch at day {}",
                day
            );

            let expected_total = EmissionSchedule::block_reward(height);
            let expected_miner = EmissionSchedule::miner_reward(height);
            let expected_dev = EmissionSchedule::developer_reward(height);
            assert_eq!(
                coinbase.outputs[0].amount,
                expected_miner,
                "mainnet miner reward mismatch at day {}",
                day
            );
            assert_eq!(
                coinbase.outputs[1].amount,
                expected_dev,
                "mainnet dev reward mismatch at day {}",
                day
            );
            assert_eq!(
                coinbase.outputs[0]
                    .amount
                    .saturating_add(coinbase.outputs[1].amount),
                expected_total,
                "mainnet total reward mismatch at day {}",
                day
            );
            assert!(
                expected_total <= prev_reward,
                "mainnet emission must be non-increasing: day {} reward {} > prev {}",
                day,
                expected_total,
                prev_reward
            );
            prev_reward = expected_total;

            let parents = if day == 0 {
                Vec::new()
            } else {
                vec![prev_hash.clone()]
            };
            let block = Block {
                header: BlockHeader::new_with_defaults(
                    1,
                    String::new(),
                    parents,
                    coinbase.hash.clone(),
                    timestamp,
                    0,
                    1,
                    height,
                ),
                body: BlockBody {
                    transactions: vec![coinbase],
                },
            };

            let mined = miner.mine_block(block);
            assert!(
                !mined.header.hash.is_empty(),
                "mainnet mining failed at day {}",
                day
            );
            assert!(
                Miner::verify_pow(&mined),
                "invalid mainnet PoW at day {}",
                day
            );
            prev_hash = mined.header.hash;
        }
    }
}

#[cfg(test)]
mod genesis_tests_comprehensive {
    use crate::config::genesis::genesis::{
        compute_merkle_root, create_genesis_block, verify_genesis, GENESIS_HEIGHT, GENESIS_REWARD,
        GENESIS_TIMESTAMP,
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
        let total: u64 = g.body.transactions[0]
            .outputs
            .iter()
            .map(|o| o.amount)
            .sum();
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
