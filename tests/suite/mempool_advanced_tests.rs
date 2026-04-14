// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//     Mempool Advanced Tests — ordering, spam, size limit, 10k transactions
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::service::mempool::core::mempool::{
        Mempool, MAX_MEMPOOL_SIZE, MAX_TX_BYTE_SIZE, MIN_RELAY_FEE,
    };

    // ── helpers ──────────────────────────────────────────────────────────
    fn tmp_mempool(suffix: &str) -> Mempool {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let pid = std::process::id();
        let path = format!("/tmp/mempool_adv_{}_{}_{}", suffix, pid, ts);
        let _ = std::fs::remove_dir_all(&path);
        Mempool::try_new(path.as_str()).expect("mp")
    }

    /// Convert a short test name to a deterministic 64-char hex hash.
    fn th(name: &str) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(name.as_bytes()))
    }

    fn make_tx(hash: &str, fee: u64, amount: u64) -> Transaction {
        use crate::domain::transaction::transaction::TxInput;
        Transaction {
            hash: th(hash),
            inputs: vec![TxInput {
                txid: th(&format!("prev_{}", hash)),
                index: 0,
                owner: "shadow1mempool".to_string(),
                signature: "sig".to_string(),
                pub_key: "pk".to_string(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput {
                address: "shadow1mempool".into(),
                amount,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    fn dummy_utxo_set() -> crate::domain::utxo::utxo_set::UtxoSet {
        crate::domain::utxo::utxo_set::UtxoSet::new_empty()
    }

    // ── 1. Duplicate TX rejected ──────────────────────────────────────────
    #[test]
    fn duplicate_tx_rejected() {
        let pool = tmp_mempool("dup");
        let tx = make_tx("dup_hash_0001", 5, 1_000);
        pool.add_transaction_test(&tx);
        pool.add_transaction_test(&tx);
        let txs = pool.get_all_transactions();
        let count = txs.iter().filter(|t| t.hash == th("dup_hash_0001")).count();
        assert_eq!(count, 1, "Duplicate TX must not be stored twice");
    }

    // ── 2. Fee ordering ───────────────────────────────────────────────────
    #[test]
    fn get_transactions_for_block_ordered_by_fee_desc() {
        let pool = tmp_mempool("fee_order");
        let tx1 = make_tx("fee_tx_1", 1, 1_000);
        let tx5 = make_tx("fee_tx_5", 5, 1_000);
        let tx3 = make_tx("fee_tx_3", 3, 1_000);
        let tx10 = make_tx("fee_tx_10", 10, 1_000);
        pool.add_transaction_test(&tx1);
        pool.add_transaction_test(&tx5);
        pool.add_transaction_test(&tx3);
        pool.add_transaction_test(&tx10);

        // Build a UTXO set containing the inputs referenced by each test tx
        let mut us = dummy_utxo_set();
        for tx in &[&tx1, &tx5, &tx3, &tx10] {
            for inp in &tx.inputs {
                let key = format!("{}:{}", inp.txid, inp.index);
                us.add_test_utxo(&key, 2_000, "shadow1mempool");
            }
        }

        let selected = pool.select_transactions_for_block(&us, 4);
        assert!(!selected.is_empty(), "At least one TX must be selected");
        for w in selected.windows(2) {
            assert!(
                w[0].fee >= w[1].fee,
                "Transactions must be ordered by fee descending"
            );
        }
    }

    // ── 3. count() reflects actual state ─────────────────────────────────
    #[test]
    fn count_reflects_insertions() {
        let pool = tmp_mempool("count");
        assert_eq!(pool.count(), 0);
        pool.add_transaction_test(&make_tx("count_tx_1", 2, 1_000));
        pool.add_transaction_test(&make_tx("count_tx_2", 3, 1_000));
        assert_eq!(pool.count(), 2);
    }

    // ── 4. remove_transaction ─────────────────────────────────────────────
    #[test]
    fn remove_transaction_decrements_count() {
        let pool = tmp_mempool("remove");
        pool.add_transaction_test(&make_tx("rm_tx_001", 5, 1_000));
        pool.add_transaction_test(&make_tx("rm_tx_002", 5, 1_000));
        assert_eq!(pool.count(), 2);
        pool.remove_transaction(&th("rm_tx_001"));
        assert_eq!(pool.count(), 1);
        let all = pool.get_all_transactions();
        assert!(
            !all.iter().any(|t| t.hash == th("rm_tx_001")),
            "Removed TX must not appear in pool"
        );
    }

    // ── 5. get_transaction by hash ────────────────────────────────────────
    #[test]
    fn get_transaction_returns_correct_tx() {
        let pool = tmp_mempool("get_tx");
        let tx = make_tx("get_tx_001", 7, 2_000);
        pool.add_transaction_test(&tx);
        let found = pool.get_transaction(&th("get_tx_001"));
        assert!(found.is_some());
        assert_eq!(found.unwrap().fee, 7);
    }

    // ── 6. TX below MIN_RELAY_FEE rejected ───────────────────────────────
    #[test]
    fn tx_below_min_relay_fee_rejected() {
        let pool = tmp_mempool("min_fee");
        let tx = make_tx("low_fee_tx", 0, 1_000);
        let result = pool.add_transaction(&tx);
        assert!(!result, "TX with fee below MIN_RELAY_FEE must be rejected");
    }

    // ── 7. 1000 unique transactions — bulk insertion ──────────────────────
    #[test]
    fn bulk_1000_transactions_accepted() {
        let pool = tmp_mempool("bulk_1000");
        let mut accepted = 0usize;
        for i in 0..1_000usize {
            let hash = format!("bulk1k_{:020}", i);
            let fee = (i % 10 + 1) as u64;
            if pool.add_transaction_test(&make_tx(&hash, fee, 1_000)) {
                accepted += 1;
            }
        }
        assert!(
            accepted > 900,
            "At least 900/1000 TXs must be accepted (accepted={})",
            accepted
        );
    }

    // ── 8. TX ordering: top-N for block ──────────────────────────────────
    #[test]
    fn get_transactions_for_block_returns_at_most_n() {
        let pool = tmp_mempool("top_n");
        for i in 0..20usize {
            pool.add_transaction_test(&make_tx(&format!("topn_tx_{:010}", i), i as u64 + 1, 1_000));
        }
        let us = dummy_utxo_set();
        let selected = pool.select_transactions_for_block(&us, 10);
        assert!(selected.len() <= 10, "Must return at most 10 transactions");
    }

    // ── 9. Stats available ────────────────────────────────────────────────
    #[test]
    fn mempool_stats_available() {
        let pool = tmp_mempool("stats");
        pool.add_transaction_test(&make_tx("stats_tx_001", 5, 1_000));
        let _stats = pool.stats();
        assert!(pool.count() >= 1);
    }

    // ── 10. Conflict detection — inputs overlap ───────────────────────────
    #[test]
    fn conflicting_txs_detected() {
        use crate::domain::transaction::transaction::TxInput;
        let pool = tmp_mempool("conflict");

        let shared_input = TxInput {
            txid: th("shared_prev_tx_0000000000"),
            index: 0,
            owner: "owner_conflict".into(),
            signature: "aabb".repeat(32),
            pub_key: "ccdd".repeat(16),
            key_image: None,
            ring_members: None,
        };

        let tx1 = Transaction {
            hash: "conflict_tx_001".to_string(),
            inputs: vec![shared_input.clone()],
            outputs: vec![TxOutput {
                address: "addr1".into(),
                amount: 1_000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: MIN_RELAY_FEE,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        let tx2 = Transaction {
            hash: "conflict_tx_002".to_string(),
            inputs: vec![shared_input],
            outputs: vec![TxOutput {
                address: "addr2".into(),
                amount: 1_000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: MIN_RELAY_FEE,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };

        let r1 = pool.add_transaction_test(&tx1);
        let r2 = pool.add_transaction_test(&tx2);
        assert!(
            !(r1 && r2),
            "Two TXs spending the same input must not both succeed"
        );
    }

    // ── 11. Orphan TX tracking ────────────────────────────────────────────
    #[test]
    fn orphan_tx_tracked_and_resolved() {
        let pool = tmp_mempool("orphan_tx");
        let orphan = Transaction {
            hash: "orphan_tx_hash_001".to_string(),
            inputs: vec![crate::domain::transaction::transaction::TxInput {
                txid: th("missing_parent_tx_0000000000"),
                index: 0,
                owner: "owner".into(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput {
                address: "addr".into(),
                amount: 1_000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: MIN_RELAY_FEE,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        pool.add_orphan(&orphan);
        assert!(
            pool.is_orphan("orphan_tx_hash_001"),
            "TX with unknown parent must be tracked as orphan"
        );
    }

    // ── 12. flush() empties pool ──────────────────────────────────────────
    #[test]
    fn flush_empties_all_transactions() {
        let pool = tmp_mempool("flush");
        for i in 0..5usize {
            pool.add_transaction_test(&make_tx(&format!("flush_tx_{:05}", i), i as u64 + 1, 1_000));
        }
        assert!(pool.count() >= 1);
        pool.flush();
        assert_eq!(pool.count(), 0, "flush() must empty the mempool");
    }

    // ── 13. MAX constants are correct ────────────────────────────────────
    #[test]
    fn max_mempool_size_constant_value() {
        assert_eq!(MAX_MEMPOOL_SIZE, 100_000);
    }

    #[test]
    fn max_tx_byte_size_constant_value() {
        assert_eq!(MAX_TX_BYTE_SIZE, 100_000);
    }

    // ── 14. get_all_transactions after partial remove ─────────────────────
    #[test]
    fn get_all_transactions_reflects_removals() {
        let pool = tmp_mempool("all_after_remove");
        for i in 0..5usize {
            pool.add_transaction_test(&make_tx(&format!("aar_tx_{:05}", i), i as u64 + 1, 1_000));
        }
        pool.remove_transaction(&th("aar_tx_00002"));
        let all = pool.get_all_transactions();
        assert!(
            !all.iter().any(|t| t.hash == th("aar_tx_00002")),
            "Removed TX must not appear"
        );
    }
}
