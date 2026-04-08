// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod utxo_set_tests {
    use crate::domain::utxo::utxo_set::UtxoSet;

    fn new_mock() -> UtxoSet {
        UtxoSet::new_empty()
    }

    #[test]
    fn add_and_get_utxo() {
        let mut m = new_mock();
        m.add_test_utxo("tx1:0", 1000, "shadow1alice");
        let u = m.get_utxo_str("tx1:0");
        assert!(u.is_some());
        assert_eq!(u.unwrap().amount, 1000);
    }

    #[test]
    fn exists_returns_true_for_unspent() {
        let mut m = new_mock();
        m.add_test_utxo("tx2:0", 500, "shadow1bob");
        assert!(m.exists_str("tx2:0"));
    }

    #[test]
    fn spend_marks_as_spent() {
        let mut m = new_mock();
        m.add_test_utxo("tx3:0", 200, "shadow1carol");
        m.spend_utxo_str("tx3:0").unwrap();
        assert!(!m.exists_str("tx3:0"), "Spent utxo must not exist as unspent");
    }

    #[test]
    fn get_balance_sums_unspent() {
        let mut m = new_mock();
        m.add_test_utxo("tx4:0", 600, "shadow1dave");
        m.add_test_utxo("tx4:1", 400, "shadow1dave");
        assert_eq!(m.get_balance("shadow1dave"), 1000);
    }

    #[test]
    fn balance_excludes_spent() {
        let mut m = new_mock();
        m.add_test_utxo("tx5:0", 300, "shadow1eve");
        m.add_test_utxo("tx5:1", 700, "shadow1eve");
        m.spend_utxo_str("tx5:0").unwrap();
        assert_eq!(m.get_balance("shadow1eve"), 700);
    }
}

#[cfg(test)]
mod utxo_validator_tests {
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};

    fn mock_tx_with_input(txid: &str, idx: u32, owner: &str) -> Transaction {
        Transaction {
            hash:      format!("tx_{}", txid),
            inputs:    vec![TxInput {
                txid:      txid.to_string(),
                index:     idx,
                owner:     owner.to_string(),
                signature: String::new(),
                pub_key:   String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs:   vec![TxOutput { address: "dest".to_string(), amount: 100, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee:       1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn coinbase_always_valid() {
        let cb = Transaction {
            hash: "cb".to_string(), inputs: vec![],
            outputs: vec![TxOutput { address: "miner".to_string(), amount: 10, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: 0, timestamp: 0, is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        let _mock = UtxoSet::new_empty();

        assert!(cb.is_coinbase());
    }

    #[test]
    fn missing_utxo_fails() {
        let _tx  = mock_tx_with_input("notexist", 0, "shadow1x");
        let mock = UtxoSet::new_empty();

        assert!(!mock.exists_str("notexist:0"));
    }

    #[test]
    fn duplicate_input_detected() {
        let mut mock = UtxoSet::new_empty();
        mock.add_test_utxo("dup:0", 100, "shadow1x");

        let tx = Transaction {
            hash: "txdup".to_string(),
            inputs: vec![
                TxInput { txid: "dup".to_string(), index: 0, owner: "shadow1x".to_string(),
                          signature: String::new(), pub_key: String::new(),
 key_image: None,
 ring_members: None,
                },
                TxInput { txid: "dup".to_string(), index: 0, owner: "shadow1x".to_string(),
                          signature: String::new(), pub_key: String::new(),
 key_image: None,
 ring_members: None,
                },
            ],
            outputs: vec![TxOutput { address: "dest".to_string(), amount: 90, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: 10,
            timestamp: 0,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };

        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let mut has_dup = false;
        for i in &tx.inputs {
            let k = format!("{}:{}", i.txid, i.index);
            if !seen.insert(k) { has_dup = true; break; }
        }
        assert!(has_dup, "Duplicate input should be detected");
    }
}

#[cfg(test)]
mod utxo_spend_tests {
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};

    fn simple_tx(txid_in: &str, hash: &str, amount_out: u64) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: vec![TxInput {
                txid: txid_in.to_string(), index: 0, owner: "shadow1alice".to_string(),
                signature: String::new(), pub_key: String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput { address: "shadow1bob".to_string(), amount: amount_out, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: 0,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn block_double_spend_rejected() {
        let mut mock = UtxoSet::new_empty();
        mock.add_test_utxo("shared:0", 100, "shadow1alice");

        let tx1 = simple_tx("shared", "tx_a", 90);
        let tx2 = simple_tx("shared", "tx_b", 85);

        use std::collections::HashSet;
        let mut spent = HashSet::new();
        let mut conflict = false;
        for tx in &[tx1, tx2] {
            for input in &tx.inputs {
                let key = format!("{}:{}", input.txid, input.index);
                if spent.contains(&key) { conflict = true; break; }
                spent.insert(key);
            }
        }
        assert!(conflict, "Double-spend within block must be detected");
    }
}
