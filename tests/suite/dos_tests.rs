// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
    use crate::domain::transaction::tx_validator::validate_tx;
    use crate::domain::transaction::tx_validator::{
        MAX_OUTPUT_AMOUNT, MAX_TX_INPUTS, MAX_TX_OUTPUTS,
    };
    use crate::config::consensus::consensus_params::ConsensusParams;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;
    use crate::engine::dag::security::dos_protection::DosProtection;
    use crate::engine::dag::security::spam_filter::SpamFilter;

    fn make_tx_with_n_outputs(n: usize) -> Transaction {
        use crate::domain::transaction::tx_validator::DUST_LIMIT;
        Transaction {
            hash: format!("dos_tx_{}", n),
            inputs: vec![],
            outputs: (0..n)
                .map(|i| TxOutput {
                    address: format!("addr{}", i),
                    amount: DUST_LIMIT, // at least DUST_LIMIT to pass sum_outputs
                    commitment: None,
                    range_proof: None,
                    ephemeral_pubkey: None,
                    one_time_pubkey: None,
                    encrypted_amount: None,
                })
                .collect(),
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: true, // coinbase has no inputs; tests output limits only
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    fn make_tx_with_n_inputs(n: usize) -> Transaction {
        Transaction {
            hash: format!("dos_tx_in_{}", n),
            inputs: (0..n)
                .map(|i| TxInput {
                    txid: format!("prev{}", i),
                    index: 0,
                    owner: String::new(),
                    signature: String::new(),
                    pub_key: String::new(),
                    key_image: None,
                    ring_members: None,
                    ring_signature: None,
                    ring_commitments: None,
                    pseudo_commitment: None,
                    shield_blinding: None,
                })
                .collect(),
            outputs: vec![TxOutput {
                address: "addr1".into(),
                amount: 1,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
                one_time_pubkey: None,
                encrypted_amount: None,
            }],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn max_tx_outputs_limit_enforced() {
        let tx = make_tx_with_n_outputs(MAX_TX_OUTPUTS + 1);
        assert!(
            !validate_tx(&tx),
            "TX with too many outputs should be rejected"
        );
    }

    #[test]
    fn max_tx_inputs_limit_enforced() {
        let tx = make_tx_with_n_inputs(MAX_TX_INPUTS + 1);
        assert!(
            !validate_tx(&tx),
            "TX with too many inputs should be rejected"
        );
    }

    #[test]
    fn over_limit_outputs_rejected() {
        let tx_over = make_tx_with_n_outputs(MAX_TX_OUTPUTS + 1);
        assert!(
            !validate_tx(&tx_over),
            "TX exceeding MAX_TX_OUTPUTS should be rejected"
        );
    }

    #[test]
    fn at_limit_outputs_passes() {
        let tx_at = make_tx_with_n_outputs(MAX_TX_OUTPUTS);
        assert!(
            validate_tx(&tx_at),
            "TX at exactly MAX_TX_OUTPUTS should pass"
        );
    }

    #[test]
    fn max_output_amount_enforced() {
        let tx = Transaction {
            hash: "overflow_tx".into(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "addr1".into(),
                amount: MAX_OUTPUT_AMOUNT + 1,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
                one_time_pubkey: None,
                encrypted_amount: None,
            }],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        assert!(
            !validate_tx(&tx),
            "TX with output exceeding MAX_OUTPUT_AMOUNT should fail"
        );
    }

    // ── Regression (B1-H02): Shield tx outputs carry amount=0 by design (value
    //    hidden in the commitment) and must be exempt from the "zero output" rule
    //    in the structural DoS/spam validators, exactly like RingCT confidential
    //    outputs. Before the fix `is_conf` checked only is_confidential(), so any
    //    block carrying a Shield tx was rejected chain-wide (shield unminable).
    fn shield_tx(hash: &str) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: vec![TxInput {
                txid: "a".repeat(64), // valid 64-hex so utxo_key() succeeds
                index: 0,
                owner: String::new(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
                ring_signature: None,
                ring_commitments: None,
                pseudo_commitment: None,
                shield_blinding: None,
            }],
            outputs: vec![TxOutput {
                address: "SD1pshieldoutputaddress000000000000000000".into(),
                amount: 0, // shield output — value is in the commitment
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
                one_time_pubkey: None,
                encrypted_amount: None,
            }],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Shield,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn shield_zero_output_passes_dos_protection() {
        let tx = shield_tx("shield_dos_regression");
        let res = DosProtection::validate_transaction(&tx);
        assert!(
            res.is_ok(),
            "Shield tx (amount=0 outputs) must not be rejected by DoS protection: {:?}",
            res.reason
        );

        // Differential: the SAME tx as a transparent transfer is still rejected.
        let mut transparent = tx.clone();
        transparent.tx_type = TxType::Transfer;
        let res_t = DosProtection::validate_transaction(&transparent);
        assert!(
            !res_t.is_ok() && res_t.reason.as_deref() == Some("Zero output"),
            "transparent tx with a zero-amount output must fail with 'Zero output', got {:?}",
            res_t.reason
        );
    }

    #[test]
    fn shield_zero_output_passes_spam_filter() {
        let coinbase = Transaction {
            hash: "cb_shield_block".into(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "shadow1miner".into(),
                amount: 1_000_000_000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
                one_time_pubkey: None,
                encrypted_amount: None,
            }],
            fee: 0,
            timestamp: 1735689600,
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        let block = Block {
            header: BlockHeader::new_with_defaults(
                1,
                "shield_block_hash".into(),
                vec!["parent_hash".into()],
                "merkle_root".into(),
                1735689600,
                0,
                ConsensusParams::GENESIS_DIFFICULTY,
                1,
            ),
            body: BlockBody {
                transactions: vec![coinbase, shield_tx("shield_spam_regression")],
            },
        };
        assert!(
            SpamFilter::validate(&block),
            "a block carrying a valid Shield tx must pass the spam filter"
        );
    }

    // Regression (shield structural validation): the block path validates each tx
    // via TxValidator::validate_structure_for_network, whose sum_outputs() dust
    // floor rejected amount=0 shield outputs, so a mined block carrying a shield tx
    // failed with "tx N structural validation failed" and shield stayed unminable
    // on-chain (found by live testnet E2E, not covered by the dos/spam fix).
    #[test]
    fn shield_zero_output_passes_structural_validation() {
        use crate::config::node::node_config::NetworkMode;
        use crate::domain::transaction::tx_hash::TxHash;
        use crate::domain::transaction::tx_validator::TxValidator;

        let mut tx = shield_tx("shield_structural_regression");
        tx.hash = TxHash::hash_for_network(&tx, &NetworkMode::Mainnet);
        assert!(
            TxValidator::validate_structure_for_network(&tx, &NetworkMode::Mainnet),
            "shield tx (amount=0 outputs) must pass block structural validation"
        );

        // Differential: a transparent tx with a zero (sub-dust) output still fails.
        let mut transparent = shield_tx("transparent_dust_regression");
        transparent.tx_type = TxType::Transfer;
        transparent.hash = TxHash::hash_for_network(&transparent, &NetworkMode::Mainnet);
        assert!(
            !TxValidator::validate_structure_for_network(&transparent, &NetworkMode::Mainnet),
            "transparent tx with a zero-amount (sub-dust) output must fail structural validation"
        );
    }

    // Regression (B1-M04): the spam filter must ALLOW duplicate (address, amount)
    // outputs — two equal payments to one address are a valid tx shape (dos_protection
    // allows them); rejecting them censored valid txs and their blocks chain-wide.
    #[test]
    fn spam_filter_allows_duplicate_outputs() {
        let out = |addr: &str, amt: u64| TxOutput {
            address: addr.into(),
            amount: amt,
            commitment: None,
            range_proof: None,
            ephemeral_pubkey: None,
            one_time_pubkey: None,
            encrypted_amount: None,
        };
        let coinbase = Transaction {
            hash: "cb_dup_block".into(),
            inputs: vec![],
            outputs: vec![out("shadow1miner", 1_000_000_000)],
            fee: 0,
            timestamp: 1735689600,
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        let dup_tx = Transaction {
            hash: "dup_out_tx".into(),
            inputs: vec![TxInput {
                txid: "b".repeat(64),
                index: 0,
                owner: String::new(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
                ring_signature: None,
                ring_commitments: None,
                pseudo_commitment: None,
                shield_blinding: None,
            }],
            // Two identical (address, amount) outputs — must be allowed.
            outputs: vec![out("shadow1dup", 1000), out("shadow1dup", 1000)],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        let block = Block {
            header: BlockHeader::new_with_defaults(
                1,
                "dup_block_hash".into(),
                vec!["parent_hash".into()],
                "merkle_root".into(),
                1735689600,
                0,
                ConsensusParams::GENESIS_DIFFICULTY,
                1,
            ),
            body: BlockBody {
                transactions: vec![coinbase, dup_tx],
            },
        };
        assert!(
            SpamFilter::validate(&block),
            "spam filter must allow duplicate (address, amount) outputs"
        );
    }

    #[test]
    fn dos_constants_are_reasonable() {
        const { assert!(MAX_TX_INPUTS >= 50) }; // MAX_TX_INPUTS should be at least 50
        const { assert!(MAX_TX_OUTPUTS >= 100) }; // MAX_TX_OUTPUTS should be at least 100
        const { assert!(MAX_TX_INPUTS <= 10_000) }; // MAX_TX_INPUTS should not exceed 10,000
        const { assert!(MAX_TX_OUTPUTS <= 10_000) }; // MAX_TX_OUTPUTS should not exceed 10,000
    }
}
