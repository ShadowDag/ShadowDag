// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::domain::transaction::tx_validator::{MAX_TX_INPUTS, MAX_TX_OUTPUTS, MAX_OUTPUT_AMOUNT};
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
    use crate::domain::transaction::tx_validator::validate_tx;

    fn make_tx_with_n_outputs(n: usize) -> Transaction {
        Transaction {
            hash:      format!("dos_tx_{}", n),
            inputs:    vec![],
            outputs:   (0..n).map(|i| TxOutput {
                address: format!("addr{}", i),
                amount: 1,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }).collect(),
            fee:       1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    fn make_tx_with_n_inputs(n: usize) -> Transaction {
        Transaction {
            hash:    format!("dos_tx_in_{}", n),
            inputs:  (0..n).map(|i| TxInput {
                txid:      format!("prev{}", i),
                index:     0,
                owner:     String::new(),
                signature: String::new(),
                pub_key:   String::new(),
                key_image: None,
                ring_members: None,
            }).collect(),
            outputs: vec![TxOutput { address: "addr1".into(), amount: 1, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee:     1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    #[test]
    fn max_tx_outputs_limit_enforced() {
        let tx = make_tx_with_n_outputs(MAX_TX_OUTPUTS + 1);
        assert!(!validate_tx(&tx), "TX with too many outputs should be rejected");
    }

    #[test]
    fn max_tx_inputs_limit_enforced() {
        let tx = make_tx_with_n_inputs(MAX_TX_INPUTS + 1);
        assert!(!validate_tx(&tx), "TX with too many inputs should be rejected");
    }

    #[test]
    fn at_limit_outputs_passes() {
        let tx_over = make_tx_with_n_outputs(MAX_TX_OUTPUTS + 1);
        assert!(!validate_tx(&tx_over));
    }

    #[test]
    fn max_output_amount_enforced() {
        let tx = Transaction {
            hash:      "overflow_tx".into(),
            inputs:    vec![],
            outputs:   vec![TxOutput {
                address: "addr1".into(),
                amount: MAX_OUTPUT_AMOUNT + 1,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee:       1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        };
        assert!(!validate_tx(&tx), "TX with output exceeding MAX_OUTPUT_AMOUNT should fail");
    }

    #[test]
    fn dos_constants_are_reasonable() {
        const { assert!(MAX_TX_INPUTS  >= 50) };  // MAX_TX_INPUTS should be at least 50
        const { assert!(MAX_TX_OUTPUTS >= 100) };  // MAX_TX_OUTPUTS should be at least 100
        const { assert!(MAX_TX_INPUTS  <= 10_000) }; // MAX_TX_INPUTS should not exceed 10,000
        const { assert!(MAX_TX_OUTPUTS <= 10_000) }; // MAX_TX_OUTPUTS should not exceed 10,000
    }
}
