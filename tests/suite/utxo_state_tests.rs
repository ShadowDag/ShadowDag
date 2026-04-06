// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//          utxo / State Tests — create, spend, balance, restart consistency
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
    use crate::domain::utxo::utxo_set::UtxoSet;

    // ── helpers ──────────────────────────────────────────────────────────
    fn tmp_store(suffix: &str) -> UtxoStore {
        let path = format!("/tmp/utxo_state_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        UtxoStore::new(path.as_str()).expect("UtxoStore::new failed")
    }

    fn tmp_utxo_set(suffix: &str) -> UtxoSet {
        UtxoSet::new(Arc::new(tmp_store(suffix)))
    }

    fn store_path(suffix: &str) -> String {
        format!("/tmp/utxo_state_{}", suffix)
    }

    // ── 1. Create utxo and retrieve it ───────────────────────────────────
    #[test]
    fn create_utxo_and_retrieve() {
        let store = tmp_utxo_set("create");
        store.add_utxo_str("txhash_0001:0", "owner_a".into(), 5_000, "shadow1addr_a".into());

        let utxo = store.get_utxo_str("txhash_0001:0");
        assert!(utxo.is_some(), "utxo must be found after insertion");
        let u = utxo.unwrap();
        assert_eq!(u.amount, 5_000);
        assert_eq!(u.owner, "owner_a");
        assert!(!u.spent, "New utxo must not be marked spent");
    }

    // ── 2. Spend utxo ────────────────────────────────────────────────────
    #[test]
    fn spend_utxo_marks_it_spent() {
        let store = tmp_utxo_set("spend");
        store.add_utxo_str("txhash_0002:0", "owner_b".into(), 3_000, "shadow1addr_b".into());
        store.spend_utxo_str("txhash_0002:0");

        let utxo = store.get_utxo_str("txhash_0002:0");
        assert!(utxo.is_some());
        assert!(utxo.unwrap().spent, "Spent utxo must have spent=true");
    }

    // ── 3. Non-existent utxo returns None ────────────────────────────────
    #[test]
    fn get_nonexistent_utxo_returns_none() {
        let store = tmp_utxo_set("nonexistent");
        let utxo = store.get_utxo_str("does_not_exist:0");
        assert!(utxo.is_none());
    }

    // ── 4. exists() check ────────────────────────────────────────────────
    #[test]
    fn exists_returns_true_after_add() {
        let store = tmp_utxo_set("exists");
        store.add_utxo_str("txhash_0004:0", "owner_d".into(), 1_000, "shadow1addr_d".into());
        assert!(store.exists_str("txhash_0004:0"));
    }

    #[test]
    fn exists_returns_false_for_unknown_key() {
        let store = tmp_utxo_set("exists_false");
        assert!(!store.exists_str("nonexistent_key:99"));
    }

    // ── 5. exists_spendable — unspent utxo ───────────────────────────────
    #[test]
    fn exists_spendable_returns_true_for_unspent_regular_utxo() {
        let store = tmp_utxo_set("spendable_regular");
        store.add_utxo_str("txhash_0005:0", "owner_e".into(), 2_000, "shadow1addr_e".into());
        // Non-coinbase utxo → no maturity check
        assert!(store.exists_spendable_str("txhash_0005:0", 100));
    }

    #[test]
    fn exists_spendable_returns_false_for_spent_utxo() {
        let store = tmp_utxo_set("spendable_spent");
        store.add_utxo_str("txhash_0006:0", "owner_f".into(), 2_000, "shadow1addr_f".into());
        store.spend_utxo_str("txhash_0006:0");
        assert!(!store.exists_spendable_str("txhash_0006:0", 100));
    }

    // ── 6. Coinbase maturity check ────────────────────────────────────────
    #[test]
    fn coinbase_utxo_immature_is_not_spendable() {
        let store = tmp_utxo_set("cb_maturity");
        store.add_utxo_coinbase_str(
            "cb_txhash_0007:0",
            "owner_g".into(),
            10_000,
            "shadow1addr_g".into(),
            50, // created at height 50
        );
        // At height 100, confirmations = 50 < COINBASE_MATURITY (100)
        assert!(
            !store.exists_spendable_str("cb_txhash_0007:0", 100),
            "Immature coinbase must not be spendable"
        );
    }

    #[test]
    fn coinbase_utxo_mature_is_spendable() {
        let store = tmp_utxo_set("cb_mature");
        store.add_utxo_coinbase_str(
            "cb_txhash_0008:0",
            "owner_h".into(),
            10_000,
            "shadow1addr_h".into(),
            0, // created at genesis
        );
        // At height 1100, confirmations = 1100 >= COINBASE_MATURITY (1000)
        assert!(
            store.exists_spendable_str("cb_txhash_0008:0", 1100),
            "Mature coinbase must be spendable"
        );
    }

    // ── 7. get_balance ────────────────────────────────────────────────────
    #[test]
    fn get_balance_sums_unspent_utxos_for_address() {
        let store = tmp_utxo_set("balance_sum");
        let addr = "shadow1balance_addr".to_string();
        store.add_utxo_str("aa00000000000000000000000000000000000000000000000000000000000001:0", "owner".into(), 1_000, addr.clone());
        store.add_utxo_str("aa00000000000000000000000000000000000000000000000000000000000002:0", "owner".into(), 2_000, addr.clone());
        store.add_utxo_str("aa00000000000000000000000000000000000000000000000000000000000003:0", "owner".into(), 3_000, addr.clone());

        let balance = store.get_balance(&addr);
        assert_eq!(balance, 6_000, "Balance must sum all unspent utxos");
    }

    #[test]
    fn get_balance_excludes_spent_utxos() {
        let store = tmp_utxo_set("balance_spent");
        let addr = "shadow1balance_spent_addr".to_string();
        store.add_utxo_str("bb00000000000000000000000000000000000000000000000000000000000001:0", "owner".into(), 5_000, addr.clone());
        store.add_utxo_str("bb00000000000000000000000000000000000000000000000000000000000002:0", "owner".into(), 3_000, addr.clone());
        store.spend_utxo_str("bb00000000000000000000000000000000000000000000000000000000000001:0");

        let balance = store.get_balance(&addr);
        assert_eq!(balance, 3_000, "Spent utxos must not count towards balance");
    }

    // ── 8. spend_utxo_checked — double spend returns error ───────────────
    #[test]
    fn double_spend_returns_error() {
        let store = tmp_utxo_set("double_spend");
        store.add_utxo_str("ds_tx_001:0", "owner_ds".into(), 5_000, "shadow1ds".into());
        store.spend_utxo_checked_str("ds_tx_001:0", 200).unwrap(); // first spend OK
        let result = store.spend_utxo_checked_str("ds_tx_001:0", 200);
        assert!(result.is_err(), "Second spend of same utxo must return error");
    }

    // ── 9. Persistence across reopen (simulates node restart) ────────────
    #[test]
    fn utxo_persists_after_store_reopen() {
        let path = store_path("persist");
        let _ = std::fs::remove_dir_all(&path);

        // First session: add a utxo
        {
            let store = UtxoStore::new(path.as_str()).expect("open failed");
            let utxo_set = UtxoSet::new(Arc::new(store));
            utxo_set.add_utxo_str("persist_tx:0", "owner_p".into(), 9_999, "shadow1persist".into());
        }

        // Second session: reopen and check
        {
            let store = UtxoStore::new(path.as_str()).expect("open failed");
            let utxo_set = UtxoSet::new(Arc::new(store));
            let utxo = utxo_set.get_utxo_str("persist_tx:0");
            assert!(utxo.is_some(), "utxo must persist after store reopen");
            assert_eq!(utxo.unwrap().amount, 9_999);
        }
    }

    // ── 10. Spent state persists after reopen ─────────────────────────────
    #[test]
    fn spent_state_persists_after_reopen() {
        let path = store_path("spent_persist");
        let _ = std::fs::remove_dir_all(&path);

        {
            let store = UtxoStore::new(path.as_str()).expect("open failed");
            let utxo_set = UtxoSet::new(Arc::new(store));
            utxo_set.add_utxo_str("sp_tx:0", "owner_sp".into(), 7_000, "shadow1sp".into());
            utxo_set.spend_utxo_str("sp_tx:0");
        }

        {
            let store = UtxoStore::new(path.as_str()).expect("open failed");
            let utxo_set = UtxoSet::new(Arc::new(store));
            let utxo = utxo_set.get_utxo_str("sp_tx:0").unwrap();
            assert!(utxo.spent, "Spent flag must persist after reopen");
        }
    }

    // ── 11. export_all returns correct count ──────────────────────────────
    #[test]
    fn export_all_returns_all_utxos() {
        let store = tmp_utxo_set("export");
        for i in 0..5u32 {
            store.add_utxo_str(
                &format!("export_tx_{:010}:0", i),
                "owner".into(),
                1_000 * (i as u64 + 1),
                "shadow1export".into(),
            );
        }
        let all = store.export_all();
        assert_eq!(all.len(), 5, "export_all must return all inserted utxos");
    }

    // ── 12. Multiple addresses — no cross-contamination ──────────────────
    #[test]
    fn balance_is_per_address() {
        let store = tmp_utxo_set("per_addr");
        store.add_utxo_str("cc00000000000000000000000000000000000000000000000000000000000001:0", "owner_x".into(), 5_000, "shadow1_x".into());
        store.add_utxo_str("cc00000000000000000000000000000000000000000000000000000000000002:0", "owner_y".into(), 8_000, "shadow1_y".into());

        assert_eq!(store.get_balance("shadow1_x"), 5_000);
        assert_eq!(store.get_balance("shadow1_y"), 8_000);
    }

    // ── 13. Balance after all utxos spent = 0 ────────────────────────────
    #[test]
    fn balance_zero_after_all_spent() {
        let store = tmp_utxo_set("zero_after_spend");
        let addr = "shadow1all_spent".to_string();
        store.add_utxo_str("zas_tx_001:0", "owner".into(), 2_000, addr.clone());
        store.spend_utxo_str("zas_tx_001:0");
        assert_eq!(store.get_balance(&addr), 0);
    }
}
