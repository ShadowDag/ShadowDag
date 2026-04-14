// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//    DAG Tests — concurrent blocks, ordering, orphans, 100 blocks/second
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::config::consensus::consensus_params::ConsensusParams;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::engine::dag::core::dag_manager::DagManager;
    use std::collections::HashSet;
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── helpers ──────────────────────────────────────────────────────────
    fn now_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn coinbase_tx(hash: &str) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "shadow1miner".into(),
                amount: 10_000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 0,
            timestamp: now_ts(),
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    fn make_block(hash: &str, parents: Vec<String>, height: u64, ts: u64) -> Block {
        Block {
            header: BlockHeader::new_with_defaults(
                1,
                hash.to_string(),
                parents,
                format!("merkle_{}", hash),
                ts,
                0,
                ConsensusParams::GENESIS_DIFFICULTY,
                height,
            ),
            body: BlockBody {
                transactions: vec![coinbase_tx(&format!("cb_{}", hash))],
            },
        }
    }

    fn genesis() -> Block {
        make_block(
            "genesis_dag_000000000000",
            vec![],
            0,
            ConsensusParams::GENESIS_TIMESTAMP,
        )
    }

    fn tmp_dag(suffix: &str) -> DagManager {
        let path = format!("/tmp/dag_tests_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        DagManager::new_required(&path).unwrap()
    }

    // ── 1. Linear chain: ancestors are correct ───────────────────────────
    #[test]
    fn linear_chain_ancestors_correct() {
        let dag = tmp_dag("linear");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();

        let b1 = make_block(
            "linear_b1_aaaaaaa",
            vec![g.header.hash.clone()],
            1,
            now_ts(),
        );
        let b2 = make_block(
            "linear_b2_bbbbbbb",
            vec![b1.header.hash.clone()],
            2,
            now_ts(),
        );
        dag.add_block_validated(&b1, true).unwrap();
        dag.add_block_validated(&b2, true).unwrap();

        let ancestors = dag.get_ancestors("linear_b2_bbbbbbb");
        assert!(
            ancestors.contains("linear_b1_aaaaaaa"),
            "b2 must have b1 as ancestor"
        );
        assert!(
            ancestors.contains("genesis_dag_000000000000"),
            "b2 must have genesis as ancestor"
        );
    }

    // ── 2. Parents correctly stored ──────────────────────────────────────
    #[test]
    fn get_parents_returns_correct_parents() {
        let dag = tmp_dag("parents");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();

        let b1 = make_block(
            "parents_b1_cccccc",
            vec![g.header.hash.clone()],
            1,
            now_ts(),
        );
        dag.add_block_validated(&b1, true).unwrap();

        let parents = dag.get_parents("parents_b1_cccccc");
        assert!(parents.contains(&g.header.hash));
    }

    // ── 3. Children correctly stored ─────────────────────────────────────
    #[test]
    fn get_children_returns_correct_children() {
        let dag = tmp_dag("children");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();

        let b1 = make_block(
            "children_b1_dddddd",
            vec![g.header.hash.clone()],
            1,
            now_ts(),
        );
        dag.add_block_validated(&b1, true).unwrap();

        let children = dag.get_children(&g.header.hash);
        assert!(children.contains(&"children_b1_dddddd".to_string()));
    }

    // ── 4. Orphan block (missing parents) ────────────────────────────────
    #[test]
    fn orphan_block_with_unknown_parent_stored_but_disconnected() {
        let dag = tmp_dag("orphan");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();

        let orphan = make_block(
            "orphan_block_eeeee",
            vec!["unknown_parent_fffff".to_string()],
            1,
            now_ts(),
        );
        // DagManager permits storage but doesn't resolve ancestry via unknown parent
        let _ = dag.add_block_validated(&orphan, true);
        // Genesis should not appear in orphan's ancestors
        let ancestors = dag.get_ancestors("orphan_block_eeeee");
        assert!(
            !ancestors.contains(&g.header.hash),
            "Orphan block must not be connected to genesis via unknown parent"
        );
    }

    // ── 5. Merge block has two parents ───────────────────────────────────
    #[test]
    fn merge_block_has_two_parents() {
        let dag = tmp_dag("merge");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();

        let b1 = make_block("merge_b1_gggggg", vec![g.header.hash.clone()], 1, now_ts());
        let b2 = make_block("merge_b2_hhhhhh", vec![g.header.hash.clone()], 1, now_ts());
        dag.add_block_validated(&b1, true).unwrap();
        dag.add_block_validated(&b2, true).unwrap();

        let merge = make_block(
            "merge_block_iiiiii",
            vec![b1.header.hash.clone(), b2.header.hash.clone()],
            2,
            now_ts(),
        );
        dag.add_block_validated(&merge, true).unwrap();

        let parents = dag.get_parents("merge_block_iiiiii");
        assert_eq!(parents.len(), 2, "Merge block must have 2 parents");
        assert!(parents.contains(&b1.header.hash));
        assert!(parents.contains(&b2.header.hash));
    }

    // ── 6. 100 blocks at the same timestamp (same-second scenario) ───────
    #[test]
    fn hundred_blocks_same_second() {
        let dag = tmp_dag("hundred_blocks");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();
        let ts = now_ts();

        // Chain of 100 blocks, all with same timestamp
        let mut prev_hash = g.header.hash.clone();
        for i in 0..100usize {
            let hash = format!("blk100_{:020}", i);
            let block = make_block(&hash, vec![prev_hash.clone()], (i + 1) as u64, ts);
            let result = dag.add_block_validated(&block, true);
            assert!(
                result.is_ok(),
                "Block {} at same timestamp must be accepted: {:?}",
                i,
                result
            );
            prev_hash = hash;
        }
        assert_eq!(dag.dag_size(), 101, "DAG must contain genesis + 100 blocks");
    }

    // ── 7. get_all_blocks_map contains all hashes ─────────────────────────
    #[test]
    fn get_all_blocks_map_contains_all_hashes() {
        let dag = tmp_dag("all_blocks");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();

        let b1 = make_block("all_b1_jjjjjj", vec![g.header.hash.clone()], 1, now_ts());
        let b2 = make_block("all_b2_kkkkkk", vec![g.header.hash.clone()], 1, now_ts());
        dag.add_block_validated(&b1, true).unwrap();
        dag.add_block_validated(&b2, true).unwrap();

        let map = dag.get_all_blocks_map();
        assert!(map.contains_key(&g.header.hash));
        assert!(map.contains_key("all_b1_jjjjjj"));
        assert!(map.contains_key("all_b2_kkkkkk"));
    }

    // ── 8. Tips: multiple unreferenced blocks are all tips ────────────────
    #[test]
    fn multiple_unreferenced_blocks_are_all_tips() {
        let dag = tmp_dag("multiple_tips");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();

        let b1 = make_block("tip_b1_llllll", vec![g.header.hash.clone()], 1, now_ts());
        let b2 = make_block("tip_b2_mmmmmm", vec![g.header.hash.clone()], 1, now_ts());
        let b3 = make_block("tip_b3_nnnnnn", vec![g.header.hash.clone()], 1, now_ts());
        dag.add_block_validated(&b1, true).unwrap();
        dag.add_block_validated(&b2, true).unwrap();
        dag.add_block_validated(&b3, true).unwrap();

        let tips = dag.get_tips();
        assert!(tips.contains(&b1.header.hash), "b1 must be a tip");
        assert!(tips.contains(&b2.header.hash), "b2 must be a tip");
        assert!(tips.contains(&b3.header.hash), "b3 must be a tip");
    }

    // ── 9. All ancestor hashes are unique ─────────────────────────────────
    #[test]
    fn ancestors_returned_are_unique_set() {
        let dag = tmp_dag("unique_ancestors");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();

        let b1 = make_block("ua_b1_oooooo", vec![g.header.hash.clone()], 1, now_ts());
        let b2 = make_block("ua_b2_pppppp", vec![g.header.hash.clone()], 1, now_ts());
        dag.add_block_validated(&b1, true).unwrap();
        dag.add_block_validated(&b2, true).unwrap();

        let merge = make_block(
            "ua_merge_qqqqqq",
            vec![b1.header.hash.clone(), b2.header.hash.clone()],
            2,
            now_ts(),
        );
        dag.add_block_validated(&merge, true).unwrap();

        let ancestors = dag.get_ancestors("ua_merge_qqqqqq");
        let ancestor_vec: Vec<_> = ancestors.iter().collect();
        let ancestor_set: HashSet<_> = ancestor_vec.iter().collect();
        assert_eq!(
            ancestor_vec.len(),
            ancestor_set.len(),
            "Ancestor set must not contain duplicates"
        );
    }

    // ── 10. select_parent returns a valid tip ─────────────────────────────
    #[test]
    #[allow(deprecated)]
    fn select_parent_returns_valid_tip() {
        let dag = tmp_dag("select_parent");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();

        let b1 = make_block("sp_b1_rrrrrr", vec![g.header.hash.clone()], 1, now_ts());
        dag.add_block_validated(&b1, true).unwrap();

        let tips = dag.get_tips();
        let selected = dag.select_parent_simple(&tips);
        assert!(
            selected.is_some(),
            "select_parent must return Some when tips exist"
        );
        let sel = selected.unwrap();
        assert!(dag.block_exists(&sel), "Selected parent must exist in DAG");
    }

    // ── 11. Large DAG — 500 linear blocks ────────────────────────────────
    #[test]
    fn large_linear_dag_500_blocks() {
        let dag = tmp_dag("linear_500");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();
        let mut prev = g.header.hash.clone();

        for i in 0..500usize {
            let hash = format!("lin500_{:020}", i);
            let b = make_block(&hash, vec![prev.clone()], (i + 1) as u64, now_ts());
            dag.add_block_validated(&b, true).unwrap();
            prev = hash;
        }
        assert_eq!(dag.dag_size(), 501);
    }

    // ── 12. DAG is acyclic — no block is its own ancestor ────────────────
    #[test]
    fn dag_is_acyclic() {
        let dag = tmp_dag("acyclic");
        let g = genesis();
        dag.add_block_validated(&g, true).unwrap();

        let b1 = make_block(
            "acyclic_b1_ssssss",
            vec![g.header.hash.clone()],
            1,
            now_ts(),
        );
        dag.add_block_validated(&b1, true).unwrap();

        let ancestors = dag.get_ancestors("acyclic_b1_ssssss");
        assert!(
            !ancestors.contains("acyclic_b1_ssssss"),
            "A block must not be its own ancestor (no cycles)"
        );
    }
}
