// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tx_hash_tests {
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
    use crate::domain::transaction::tx_hash::TxHash;

    fn make_tx() -> Transaction {
        Transaction {
            hash: String::new(),
            inputs: vec![TxInput {
                txid: "prev001".to_string(),
                index: 0,
                owner: "shadow1alice".to_string(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput {
                address: "shadow1bob".to_string(),
                amount: 1000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 10,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let tx = make_tx();
        let h1 = TxHash::hash(&tx);
        let h2 = TxHash::hash(&tx);
        assert_eq!(h1, h2, "Same tx must hash to same value");
    }

    #[test]
    fn hash_is_64_chars() {
        let tx = make_tx();
        let h = TxHash::hash(&tx);
        assert_eq!(h.len(), 64, "SHA-256 hash must be 64 hex chars");
    }

    #[test]
    fn signing_message_is_deterministic() {
        let tx = make_tx();
        let m1 = TxHash::signing_message(&tx);
        let m2 = TxHash::signing_message(&tx);
        assert_eq!(m1, m2);
    }

    #[test]
    fn hash_changes_with_fee() {
        let mut tx1 = make_tx();
        tx1.fee = 10;
        let mut tx2 = make_tx();
        tx2.fee = 20;
        assert_ne!(TxHash::hash(&tx1), TxHash::hash(&tx2));
    }

    #[test]
    fn coinbase_has_no_inputs() {
        let cb = Transaction {
            hash: "cb001".to_string(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "shadow1miner".to_string(),
                amount: 950,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 0,
            timestamp: 1735689600,
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        assert!(cb.is_coinbase());
    }
}

#[cfg(test)]
mod decoy_tests {
    use crate::domain::transaction::decoy_transaction::{DecoyTransaction, Ring};
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};

    fn fake_tx(hash: &str) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "shadow1x".to_string(),
                amount: 1,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 0,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn ring_has_one_real() {
        let real_tx = fake_tx("real1");
        let pool: Vec<Transaction> = vec![fake_tx("decoy1")];
        let ring = Ring::generate(real_tx, &pool, 2);
        assert!(ring.is_valid());
        assert_eq!(ring.len(), 2);
    }

    #[test]
    fn get_real_returns_correct_tx() {
        let real_tx = fake_tx("the_real_one");
        let pool: Vec<Transaction> = vec![fake_tx("d")];
        let ring = Ring::generate(real_tx, &pool, 2);
        let found = ring.get_real();
        assert!(found.is_some());
        assert_eq!(found.unwrap().hash, "the_real_one");
    }

    #[test]
    fn decoy_is_flagged_fake() {
        let d = DecoyTransaction::new_decoy(fake_tx("d1"), 0);
        assert!(d.is_fake());
    }

    #[test]
    fn real_is_not_fake() {
        let r = DecoyTransaction::new_real(fake_tx("r1"), 0);
        assert!(!r.is_fake());
    }

    #[test]
    fn ring_with_no_decoys_is_valid() {
        let real_tx = fake_tx("r1");
        let ring = Ring::generate(real_tx, &[], 1);
        assert!(ring.is_valid());
        assert_eq!(ring.len(), 1);
    }
}

#[cfg(test)]
mod tx_builder_tests {
    use crate::domain::transaction::tx_builder::{
        build_coinbase_at_height, build_transaction, generate_keypair,
    };

    #[test]
    fn coinbase_is_deterministic() {
        let t1 = build_coinbase_at_height(
            "shadow1miner".into(),
            "shadow1dev".into(),
            10,
            95,
            1735689600,
            1,
        );
        let t2 = build_coinbase_at_height(
            "shadow1miner".into(),
            "shadow1dev".into(),
            10,
            95,
            1735689600,
            1,
        );
        assert_eq!(t1.hash, t2.hash);
    }

    #[test]
    fn coinbase_different_heights_differ() {
        let t1 = build_coinbase_at_height("m".into(), "d".into(), 10, 95, 100, 1);
        let t2 = build_coinbase_at_height("m".into(), "d".into(), 10, 95, 100, 2);
        assert_ne!(t1.hash, t2.hash);
    }

    #[test]
    fn coinbase_rewards_sum_correctly() {
        let t = build_coinbase_at_height("miner".into(), "dev".into(), 100, 95, 100, 0);
        let total: u64 = t.outputs.iter().map(|o| o.amount).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn build_signed_transaction_succeeds() {
        let kp = generate_keypair();
        let result = build_transaction(
            vec![("prev_hash_001".to_string(), 0, kp.address.clone())],
            vec![("shadow1recipient".to_string(), 500)],
            10,
            &kp.private_key_hex,
            &kp.public_key_hex,
        );
        assert!(
            result.is_ok(),
            "build_transaction must succeed: {:?}",
            result
        );
        let tx = result.unwrap();
        assert!(!tx.inputs[0].signature.is_empty(), "Signature must be set");
        assert_eq!(
            tx.inputs[0].signature.len(),
            128,
            "ed25519 sig = 64 bytes = 128 hex chars"
        );
    }
}
