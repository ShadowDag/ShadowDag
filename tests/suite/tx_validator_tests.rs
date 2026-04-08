// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
    use crate::domain::transaction::tx_validator::{TxValidator, validate_tx, MAX_TX_OUTPUTS};
    use crate::domain::utxo::utxo_set::UtxoSet;

    fn make_tx(hash: &str, inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Transaction {
        Transaction {
            hash:      hash.to_string(),
            inputs,
            outputs,
            fee:       1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    fn make_output(address: &str, amount: u64) -> TxOutput {
        TxOutput { address: address.to_string(), amount, commitment: None, range_proof: None, ephemeral_pubkey: None }
    }

    fn make_input(txid: &str, index: u32, sig: &str, pk: &str) -> TxInput {
        TxInput {
            txid:      txid.to_string(),
            index,
            owner:     String::new(),
            signature: sig.to_string(),
            pub_key:   pk.to_string(),
            key_image: None,
            ring_members: None,
        }
    }

    #[test]
    fn free_validate_empty_outputs_fails() {
        let tx = make_tx("hash1", vec![], vec![]);
        assert!(!validate_tx(&tx), "TX with no outputs should fail");
    }

    #[test]
    fn free_validate_empty_hash_fails() {
        let tx = make_tx("", vec![], vec![make_output("addr1", 100)]);
        assert!(!validate_tx(&tx), "TX with empty hash should fail");
    }

    #[test]
    fn free_validate_zero_amount_fails() {
        let out = make_output("addr1", 0);
        let tx = make_tx("hash1", vec![], vec![out]);
        assert!(!validate_tx(&tx), "TX with zero amount output should fail");
    }

    #[test]
    fn free_validate_too_many_outputs_fails() {
        let outputs: Vec<TxOutput> = (0..=MAX_TX_OUTPUTS)
            .map(|i| make_output(&format!("addr{}", i), 1))
            .collect();
        let tx = make_tx("hash1", vec![], outputs);
        assert!(!validate_tx(&tx), "TX with too many outputs should fail");
    }

    #[test]
    fn free_validate_basic_valid_tx() {
        let mut tx = make_tx(
            "abc123",
            vec![],
            vec![make_output("addr1", 100)],
        );
        // Mark as coinbase so it passes the "non-coinbase must have inputs" rule
        tx.is_coinbase = true;
        // validate_tx structural check does not verify hash integrity
        // so a coinbase with valid outputs should pass structural checks
        assert!(validate_tx(&tx), "valid coinbase TX should pass free validation");
    }

    #[test]
    fn signing_message_is_deterministic() {
        let tx = make_tx(
            "txhash001",
            vec![make_input("prev", 0, "", "")],
            vec![make_output("addr1", 50)],
        );
        let msg1 = TxValidator::build_signing_message(&tx);
        let msg2 = TxValidator::build_signing_message(&tx);
        assert_eq!(msg1, msg2, "Signing message must be deterministic");
        assert_eq!(msg1.len(), 32, "SHA-256 output must be 32 bytes");
    }

    #[test]
    fn signing_message_differs_for_different_txs() {
        let tx1 = make_tx("hash1", vec![], vec![make_output("a", 100)]);
        let tx2 = make_tx("hash2", vec![], vec![make_output("a", 100)]);
        let msg1 = TxValidator::build_signing_message(&tx1);
        let msg2 = TxValidator::build_signing_message(&tx2);
        assert_ne!(msg1, msg2, "Different TXs must produce different signing messages");
    }

    #[test]
    fn double_spend_within_tx_detected() {
        let input1 = make_input("prev_tx", 0, "sig1", "pk1");
        let input2 = make_input("prev_tx", 0, "sig2", "pk2");
        let tx = make_tx("double_spend_tx",
            vec![input1, input2],
            vec![make_output("addr1", 100)],
        );
        let utxo_set = UtxoSet::new_empty();
        assert!(!TxValidator::validate_tx(&tx, &utxo_set),
            "Double spend within TX must be rejected");
    }

    #[test]
    fn forged_signature_rejected() {
        let fake_sig = "a".repeat(128);
        let fake_pk  = "b".repeat(64);
        let input = make_input("utxo1", 0, &fake_sig, &fake_pk);
        let tx = make_tx("forged_tx",
            vec![input],
            vec![make_output("addr1", 50)],
        );
        let mut utxo_set = UtxoSet::new_empty();

        utxo_set.add_test_utxo("utxo1:0", 100, "owner");
        assert!(!TxValidator::validate_tx(&tx, &utxo_set),
            "Forged signature must be rejected by cryptographic check");
    }

    #[test]
    fn invalid_hex_signature_rejected() {
        let input = make_input("utxo1", 0, "not-hex-!!", "also-not-hex");
        let tx = make_tx("bad_hex_tx",
            vec![input],
            vec![make_output("addr1", 50)],
        );
        let mut utxo_set = UtxoSet::new_empty();
        utxo_set.add_test_utxo("utxo1:0", 100, "owner");
        assert!(!TxValidator::validate_tx(&tx, &utxo_set),
            "Invalid hex in signature must be rejected");
    }
}
