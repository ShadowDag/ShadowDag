// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
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
            }],
            outputs: vec![TxOutput {
                address: "addr1".into(),
                amount: 100,
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

    #[test]
    fn duplicate_tx_rejected() {
        let mempool =
            Mempool::try_new(format!("/tmp/test_mempool_dup_{}", std::process::id())).expect("mp");
        let tx = make_tx("dup_hash_001", 5);
        mempool.add_transaction_test(&tx.clone());

        mempool.add_transaction_test(&tx);
        let txs = mempool.get_all_transactions();
        let count = txs.iter().filter(|t| t.hash == th("dup_hash_001")).count();
        assert_eq!(count, 1, "Duplicate TX must not be added twice");
    }

    #[test]
    fn fee_ordering_in_get_for_block() {
        let mempool =
            Mempool::try_new(format!("/tmp/test_mempool_fee_{}", std::process::id())).expect("mp");
        mempool.add_transaction_test(&make_tx("tx_fee_1", 1));
        mempool.add_transaction_test(&make_tx("tx_fee_5", 5));
        mempool.add_transaction_test(&make_tx("tx_fee_3", 3));

        // Create a dummy utxo_set for the method call
        let utxo_set = crate::domain::utxo::utxo_set::UtxoSet::new_empty();
        let selected = mempool.select_transactions_for_block(&utxo_set, 3);
        assert!(selected.len() <= 3);

        for w in selected.windows(2) {
            assert!(
                w[0].fee >= w[1].fee,
                "Transactions must be ordered by fee desc"
            );
        }
    }
}
