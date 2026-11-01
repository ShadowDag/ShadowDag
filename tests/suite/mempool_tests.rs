// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    /// Height the template block would occupy. Chosen well past every network's
    /// coinbase maturity so these tests exercise ordering/limits, not maturity.
    const TEMPLATE_HEIGHT: u64 = 10_000;

    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::service::mempool::core::mempool::{Mempool, MAX_MEMPOOL_SIZE, MAX_TX_BYTE_SIZE};

    /// Convert a short test name to a deterministic 64-char hex hash.
    fn th(name: &str) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(name.as_bytes()))
    }

    fn make_tx(hash: &str, fee: u64) -> Transaction {
        use crate::domain::transaction::transaction::TxInput;
        Transaction {
            hash: th(hash),
            inputs: vec![TxInput {
                txid: th(&format!("prev_{}", hash)),
                index: 0,
                owner: "addr1".to_string(),
                signature: "sig".to_string(),
                pub_key: "pk".to_string(),
                key_image: None,
                ring_members: None,
                ring_signature: None,
                ring_commitments: None,
                pseudo_commitment: None,
                shield_blinding: None,
            }],
            outputs: vec![TxOutput {
                address: "addr1".into(),
                amount: 100,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
                one_time_pubkey: None,
                encrypted_amount: None,
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

    #[test]
    fn max_mempool_size_constant() {
        assert_eq!(
            MAX_MEMPOOL_SIZE, 100_000,
            "MAX_MEMPOOL_SIZE from MempoolConfig"
        );
    }

    #[test]
    fn max_tx_byte_size_constant() {
        assert_eq!(
            MAX_TX_BYTE_SIZE, 100_000,
            "MAX_TX_BYTE_SIZE should be 100,000 bytes"
        );
    }

    /// A database path of this test's own, emptied before use.
    ///
    /// These were `format!("/tmp/test_mempool_{label}_{pid}")` with no cleanup,
    /// so a process whose id had been used before inherited that run's RocksDB.
    /// `add_transaction_test` checks `tx:` for a duplicate BEFORE `has_conflict`,
    /// and `has_conflict` rejects on an `inp:` key whether or not its `tx:` key
    /// still exists — so an interrupted run that left inputs indexed without
    /// their transaction made the next add fail with no duplicate detected, and
    /// `duplicate_tx_rejected` then saw zero transactions where it expected one.
    /// It took eleven full-suite runs to reproduce, and 936 of those
    /// directories had accumulated on this machine. The three other suites that
    /// name a database by process id already clear it first.
    fn fresh_db(label: &str) -> String {
        let path = format!("/tmp/test_mempool_{}_{}", label, std::process::id());
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn a_test_database_is_emptied_before_use() {
        // The helper is the fix for a flake that took eleven full-suite runs to
        // reproduce, so it needs a test of its own. Same label, same process,
        // twice: the second open must see nothing, or a previous run's `inp:`
        // keys outlive their `tx:` key and the next add is rejected as a
        // conflict with a transaction that is no longer there.
        let first = fresh_db("hermetic");
        {
            let mp = Mempool::try_new(first.clone()).expect("mp");
            mp.add_transaction_test(&make_tx("hermetic_001", 5));
            assert_eq!(mp.get_all_transactions().len(), 1, "written");
        } // dropped, so RocksDB releases the directory

        let again = fresh_db("hermetic");
        assert_eq!(again, first, "the same label must be the same path");
        let mp = Mempool::try_new(again).expect("mp");
        assert!(
            mp.get_all_transactions().is_empty(),
            "a test database must come back empty"
        );
    }

    #[test]
    fn duplicate_tx_rejected() {
        let mempool = Mempool::try_new(fresh_db("dup")).expect("mp");
        let tx = make_tx("dup_hash_001", 5);
        mempool.add_transaction_test(&tx.clone());

        mempool.add_transaction_test(&tx);
        let txs = mempool.get_all_transactions();
        let count = txs.iter().filter(|t| t.hash == th("dup_hash_001")).count();
        assert_eq!(count, 1, "Duplicate TX must not be added twice");
    }

    #[test]
    fn fee_ordering_in_get_for_block() {
        let mempool = Mempool::try_new(fresh_db("fee")).expect("mp");
        mempool.add_transaction_test(&make_tx("tx_fee_1", 1));
        mempool.add_transaction_test(&make_tx("tx_fee_5", 5));
        mempool.add_transaction_test(&make_tx("tx_fee_3", 3));

        // Create a dummy utxo_set for the method call
        let utxo_set = crate::domain::utxo::utxo_set::UtxoSet::new_empty();
        let selected = mempool.select_transactions_for_block(&utxo_set, 3, TEMPLATE_HEIGHT);
        assert!(selected.len() <= 3);

        for w in selected.windows(2) {
            assert!(
                w[0].fee >= w[1].fee,
                "Transactions must be ordered by fee desc"
            );
        }
    }
}
