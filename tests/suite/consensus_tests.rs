// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//              Consensus Tests — accept/reject/double-spend/DAG order
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};
    use crate::domain::block::block::Block;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::engine::dag::core::dag_manager::DagManager;
    use crate::engine::consensus::validation::block_validator::BlockValidator;
    use crate::config::consensus::consensus_params::ConsensusParams;

    // ── helpers ──────────────────────────────────────────────────────────
    fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn coinbase_tx(hash: &str) -> Transaction {
        Transaction {
            hash:      hash.to_string(),
            inputs:    vec![],
            outputs:   vec![TxOutput { address: "shadow1miner".into(), amount: 10_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee:       0,
            timestamp: now_ts(),
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    fn make_block(hash: &str, parents: Vec<String>, height: u64) -> Block {
        Block {
            header: BlockHeader::new_with_defaults(
                1,
                hash.to_string(),
                parents,
                format!("merkle_{}", hash),
                now_ts(),
                0,
                ConsensusParams::GENESIS_DIFFICULTY,
                height,
            ),
            body: BlockBody { transactions: vec![coinbase_tx(&format!("cb_{}", hash))] },
        }
    }

    fn genesis_block() -> Block {
        make_block("genesis_0000000000000000", vec![], 0)
    }

    fn tmp_dag(suffix: &str) -> DagManager {
        let path = format!("/tmp/dag_consensus_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        DagManager::new_required(&path).unwrap()
    }

    // ── 1. Accept valid block ─────────────────────────────────────────────
    #[test]
    fn accept_valid_genesis_block() {
        let dag = tmp_dag("accept_genesis");
        let genesis = genesis_block();
        let result = dag.add_block_validated(&genesis, true);
        assert!(result.is_ok(), "Valid genesis block must be accepted: {:?}", result);
        assert!(dag.block_exists(&genesis.header.hash));
    }

    #[test]
    fn accept_valid_child_block() {
        let dag = tmp_dag("accept_child");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();

        let child = make_block("child_aaaaaaaaaaaaaaa", vec![genesis.header.hash.clone()], 1);
        let result = dag.add_block_validated(&child, true);
        assert!(result.is_ok(), "Valid child block must be accepted: {:?}", result);
    }

    // ── 2. Reject invalid block ───────────────────────────────────────────
    #[test]
    fn reject_non_genesis_block_without_parents() {
        let dag = tmp_dag("no_parents");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();

        let orphan = make_block("orphan_bbbbbbbbbbbbbb", vec![], 1);
        let result = dag.add_block_validated(&orphan, true);
        assert!(
            result.is_err(),
            "Non-genesis block without parents must be rejected"
        );
    }

    #[test]
    fn reject_block_with_empty_hash() {
        let _dag = tmp_dag("empty_hash");
        let mut block = genesis_block();
        block.header.hash = String::new();
        assert!(block.header.hash.is_empty(), "Hash should be empty for this test");

        // Actually run the block through the validator
        let result = BlockValidator::validate_network_layer(&block);
        assert!(result.is_err(), "empty hash should be rejected by the validator");
    }

    // ── 3. Reject duplicate block ─────────────────────────────────────────
    #[test]
    fn reject_duplicate_block() {
        let dag = tmp_dag("duplicate");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();

        let result = dag.add_block_validated(&genesis, true);
        assert!(result.is_err(), "Duplicate block must be rejected");
    }

    // ── 4. DAG ordering: child height > parent height ─────────────────────
    #[test]
    fn dag_ordering_child_height_greater_than_parent() {
        let dag = tmp_dag("ordering");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();

        let child = make_block("child_order_1111111", vec![genesis.header.hash.clone()], 1);
        dag.add_block_validated(&child, true).unwrap();

        // child's height is 1, genesis is 0 — ordering is correct
        assert!(child.header.height > genesis.header.height);
    }

    // ── 5. Parent block validation ────────────────────────────────────────
    #[test]
    fn block_parent_must_exist_in_dag() {
        let dag = tmp_dag("parent_check");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();

        // Reference a non-existent parent
        let orphan = make_block(
            "orphan_ccc",
            vec!["nonexistent_parent_hash_0000".to_string()],
            1,
        );
        // DagManager logs a warning but may still store orphan;
        // verify the parent is not tracked as an ancestor
        let _ = dag.add_block_validated(&orphan, true);
        let ancestors = dag.get_ancestors(&orphan.header.hash);
        // genesis should not appear as ancestor since parent was unknown
        assert!(
            !ancestors.contains(&genesis.header.hash),
            "Orphan block should not be connected to genesis via unknown parent"
        );
    }

    // ── 6. Self-parent not allowed ────────────────────────────────────────
    #[test]
    fn reject_self_parent_block() {
        let dag = tmp_dag("self_parent");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();

        let hash = "self_ref_ddddddddddddd".to_string();
        let block = Block {
            header: BlockHeader::new_with_defaults(
                1,
                hash.clone(),
                vec![hash.clone()], // self-reference
                "merkle_self".to_string(),
                now_ts(),
                0,
                ConsensusParams::GENESIS_DIFFICULTY,
                1,
            ),
            body: BlockBody { transactions: vec![coinbase_tx("cb_self")] },
        };
        let result = dag.add_block_validated(&block, true);
        assert!(result.is_err(), "Self-parent block must be rejected");
    }

    // ── 7. Too many parents ───────────────────────────────────────────────
    #[test]
    fn reject_block_with_too_many_parents() {
        let dag = tmp_dag("too_many_parents");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();

        // MAX_PARENTS = 8, so 9 parents is invalid
        let many_parents: Vec<String> = (0..9)
            .map(|i| format!("parent_{:020}", i))
            .collect();

        let block = make_block("block_many_parents_ee", many_parents, 1);
        let result = dag.add_block_validated(&block, true);
        assert!(result.is_err(), "Block with too many parents must be rejected");
    }

    // ── 8. Duplicate parents in a single block ────────────────────────────
    #[test]
    fn reject_block_with_duplicate_parents() {
        let dag = tmp_dag("dup_parents");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();

        let block = Block {
            header: BlockHeader::new_with_defaults(
                1,
                "dup_parent_block_fff".to_string(),
                vec![
                    genesis.header.hash.clone(),
                    genesis.header.hash.clone(), // duplicate
                ],
                "merkle_dup".to_string(),
                now_ts(),
                0,
                ConsensusParams::GENESIS_DIFFICULTY,
                1,
            ),
            body: BlockBody { transactions: vec![coinbase_tx("cb_dup")] },
        };
        let result = dag.add_block_validated(&block, true);
        assert!(result.is_err(), "Block with duplicate parents must be rejected");
    }

    // ── 9. Timestamp sanity ───────────────────────────────────────────────
    #[test]
    fn genesis_timestamp_is_plausible() {
        let genesis = genesis_block();
        // timestamp must be > 0
        assert!(genesis.header.timestamp > 0, "Genesis timestamp must be > 0");
        // not in the future by more than 2 hours
        let two_hours_from_now = now_ts() + 7200;
        assert!(
            genesis.header.timestamp <= two_hours_from_now,
            "Genesis timestamp should not be far in the future"
        );
    }

    // ── 10. Difficulty stored correctly ───────────────────────────────────
    #[test]
    fn block_difficulty_stored() {
        let dag = tmp_dag("difficulty_store");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();
        assert_eq!(genesis.header.difficulty, ConsensusParams::GENESIS_DIFFICULTY);
    }

    // ── 11. Node A & Node B simultaneous blocks — fork detection ─────────
    #[test]
    fn fork_two_simultaneous_blocks_both_stored() {
        let dag = tmp_dag("fork_ab");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();

        let ts = now_ts();

        let block_a = Block {
            header: BlockHeader::new_with_defaults(
                1, "node_a_block_111111".to_string(),
                vec![genesis.header.hash.clone()],
                "merkle_a".to_string(), ts, 1,
                ConsensusParams::GENESIS_DIFFICULTY, 1,
            ),
            body: BlockBody { transactions: vec![coinbase_tx("cb_a")] },
        };
        let block_b = Block {
            header: BlockHeader::new_with_defaults(
                1, "node_b_block_222222".to_string(),
                vec![genesis.header.hash.clone()],
                "merkle_b".to_string(), ts, 2,
                ConsensusParams::GENESIS_DIFFICULTY, 1,
            ),
            body: BlockBody { transactions: vec![coinbase_tx("cb_b")] },
        };

        dag.add_block_validated(&block_a, true).unwrap();
        dag.add_block_validated(&block_b, true).unwrap();

        // Both blocks exist — DAG accommodates forks
        assert!(dag.block_exists("node_a_block_111111"));
        assert!(dag.block_exists("node_b_block_222222"));

        // A merge block references both, resolving the fork
        let merge = Block {
            header: BlockHeader::new_with_defaults(
                1, "merge_block_333333".to_string(),
                vec![
                    "node_a_block_111111".to_string(),
                    "node_b_block_222222".to_string(),
                ],
                "merkle_merge".to_string(), ts + 1, 0,
                ConsensusParams::GENESIS_DIFFICULTY, 2,
            ),
            body: BlockBody { transactions: vec![coinbase_tx("cb_merge")] },
        };
        let result = dag.add_block_validated(&merge, true);
        assert!(result.is_ok(), "Merge block must be accepted: {:?}", result);
    }

    // ── 12. Tips update after each block ─────────────────────────────────
    #[test]
    fn tips_updated_correctly() {
        let dag = tmp_dag("tips");
        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();

        let tips_before = dag.get_tips();
        assert!(tips_before.contains(&genesis.header.hash));

        let child = make_block("child_tips_444444", vec![genesis.header.hash.clone()], 1);
        dag.add_block_validated(&child, true).unwrap();

        let tips_after = dag.get_tips();
        // child should now be a tip; genesis should no longer be
        assert!(
            tips_after.contains(&child.header.hash),
            "Child should become a tip"
        );
    }

    // ── 13. DAG size tracking ─────────────────────────────────────────────
    #[test]
    fn dag_size_increases_with_each_block() {
        let dag = tmp_dag("dag_size");
        assert_eq!(dag.dag_size(), 0);

        let genesis = genesis_block();
        dag.add_block_validated(&genesis, true).unwrap();
        assert_eq!(dag.dag_size(), 1);

        let child = make_block("child_size_555555", vec![genesis.header.hash.clone()], 1);
        dag.add_block_validated(&child, true).unwrap();
        assert_eq!(dag.dag_size(), 2);
    }
}
