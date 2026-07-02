// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::domain::utxo::utxo_set::UtxoSet;

    #[test]
    fn add_and_get_utxo() {
        let mut set = UtxoSet::new_empty();
        set.add_test_utxo("tx1:0", 500, "alice");
        let utxo = set.get_utxo_str("tx1:0");
        assert!(utxo.is_some());
        let u = utxo.unwrap();
        assert_eq!(u.amount, 500);
        assert_eq!(u.owner, "alice");
        assert!(!u.spent);
    }

    #[test]
    fn missing_utxo_returns_none() {
        let set = UtxoSet::new_empty();
        assert!(set.get_utxo_str("nonexistent:0").is_none());
    }

    #[test]
    fn spend_marks_utxo_as_spent() {
        let mut set = UtxoSet::new_empty();
        set.add_test_utxo("tx2:0", 100, "bob");
        set.spend_utxo_str("tx2:0").unwrap();
        let utxo = set.get_utxo_str("tx2:0").unwrap();
        assert!(utxo.spent, "utxo should be marked as spent");
    }

    #[test]
    fn double_spend_detected_after_first_spend() {
        let mut set = UtxoSet::new_empty();
        set.add_test_utxo("tx3:0", 200, "carol");
        set.spend_utxo_str("tx3:0").unwrap();

        let utxo = set.get_utxo_str("tx3:0").unwrap();
        assert!(utxo.spent, "Already-spent utxo must be detectable");
    }

    #[test]
    fn balance_sum_excludes_spent() {
        let mut set = UtxoSet::new_empty();
        set.add_test_utxo("tx4:0", 300, "dave");
        set.add_test_utxo("tx4:1", 200, "dave");
        set.spend_utxo_str("tx4:0").unwrap();
        let balance = set.get_balance("dave");
        assert_eq!(balance, 200, "Balance should exclude spent utxos");
    }

    /// A minimal confidential tx: the apply path records it without signature
    /// verification and counts its declared fee, which makes it the smallest
    /// fixture that exercises fee accounting in apply_block_dag_ordered.
    fn confidential_tx_with_fee(hash: &str, fee: u64) -> crate::domain::transaction::transaction::Transaction {
        use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
        Transaction {
            hash: hash.to_string(),
            inputs: vec![TxInput {
                txid: String::new(),
                index: 0,
                owner: String::new(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: Some("ki_test_01".into()),
                ring_members: None,
                ring_signature: None,
                ring_commitments: None,
                pseudo_commitment: None,
            }],
            outputs: vec![TxOutput {
                address: String::new(),
                amount: 0,
                commitment: Some("cmt_test_01".into()),
                range_proof: None,
                ephemeral_pubkey: None,
                one_time_pubkey: Some("otk_test_01".into()),
                encrypted_amount: None,
            }],
            fee,
            timestamp: 0,
            is_coinbase: false,
            tx_type: TxType::Confidential,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn reexecuting_applied_block_drops_its_own_fees() {
        // The mechanism behind a live consensus failure: re-executing an
        // ALREADY-APPLIED block DUP-skips the block's own txs (their tx_seen
        // markers exist), so applied_fees collapses to 0 — and the
        // post-execution coinbase check then rejects a valid block by exactly
        // its fee sum. This test pins the hazardous behavior so the recompute
        // path's rollback-before-reapply guard is never removed casually.
        let set = UtxoSet::new_empty();
        let tx = confidential_tx_with_fee("conftx_reexec", 394);

        let (applied, skipped, fees) = set
            .apply_block_dag_ordered(std::slice::from_ref(&tx), 10, "blk_reexec")
            .unwrap();
        assert_eq!((applied, skipped, fees), (1, 0, 394), "first apply counts the fee");
        assert!(set.is_tx_seen(&tx.hash), "tx marked seen after apply");

        let (applied2, skipped2, fees2) = set
            .apply_block_dag_ordered(std::slice::from_ref(&tx), 10, "blk_reexec")
            .unwrap();
        assert_eq!(
            (applied2, skipped2, fees2),
            (0, 1, 0),
            "re-execution DUP-skips the block's own tx and loses its fee"
        );
    }

    #[test]
    fn rollback_then_reapply_restores_applied_fees() {
        // The fix mechanism: rolling back a partially-applied block via its
        // stored undo deletes the tx_seen markers, so a subsequent re-apply
        // counts the fees again (idempotent re-execution). The recompute path
        // relies on exactly this rollback-before-reapply sequence.
        let set = UtxoSet::new_empty();
        let tx = confidential_tx_with_fee("conftx_rollback", 394);

        let (applied, _, fees) = set
            .apply_block_dag_ordered(std::slice::from_ref(&tx), 10, "blk_rollback")
            .unwrap();
        assert_eq!((applied, fees), (1, 394));

        set.rollback_block_undo("blk_rollback").unwrap();
        assert!(
            !set.is_tx_seen(&tx.hash),
            "rollback must clear the tx_seen marker"
        );

        let (applied2, skipped2, fees2) = set
            .apply_block_dag_ordered(std::slice::from_ref(&tx), 10, "blk_rollback")
            .unwrap();
        assert_eq!(
            (applied2, skipped2, fees2),
            (1, 0, 394),
            "re-apply after rollback restores the fee accounting"
        );
    }
}
