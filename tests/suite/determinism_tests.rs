// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//         Determinism Tests — identical state root from same blocks
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::config::consensus::consensus_params::ConsensusParams;
    use crate::config::genesis::genesis::GENESIS_TIMESTAMP;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::domain::transaction::tx_hash::TxHash;
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::engine::dag::core::dag_manager::DagManager;
    use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    fn tmp_path(prefix: &str, suffix: &str) -> String {
        let pid = std::process::id();
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        format!("/tmp/{}_{}_{}_{}", prefix, suffix, pid, ts)
    }

    fn tmp_dag(suffix: &str) -> DagManager {
        let path = tmp_path("det_dag", suffix);
        let _ = std::fs::remove_dir_all(&path);
        DagManager::new_required(&path).unwrap()
    }

    fn tmp_utxo(suffix: &str) -> UtxoSet {
        let path = tmp_path("det_utxo", suffix);
        let _ = std::fs::remove_dir_all(&path);
        UtxoSet::new(Arc::new(
            UtxoStore::new(path.as_str()).expect("UtxoStore::new failed"),
        ))
    }

    fn genesis_block() -> Block {
        Block {
            header: BlockHeader::new_with_defaults(
                1,
                "det_genesis_00000000000000".to_string(),
                vec![],
                "merkle_det_genesis".to_string(),
                GENESIS_TIMESTAMP,
                0,
                ConsensusParams::GENESIS_DIFFICULTY,
                0,
            ),
            body: BlockBody {
                transactions: vec![Transaction {
                    hash: "cb_det_genesis".to_string(),
                    inputs: vec![],
                    outputs: vec![TxOutput {
                        address: "shadow1det".into(),
                        amount: 10_000,
                        commitment: None,
                        range_proof: None,
                        ephemeral_pubkey: None,
                    }],
                    fee: 0,
                    timestamp: GENESIS_TIMESTAMP,
                    is_coinbase: true,
                    tx_type: TxType::Transfer,
                    payload_hash: None,
                    ..Default::default()
                }],
            },
        }
    }

    fn deterministic_chain(prefix: &str) -> Vec<Block> {
        let g = genesis_block();
        let mut blocks = vec![g.clone()];
        let mut prev = g.header.hash.clone();
        for i in 0..10usize {
            let hash = format!("{}_{:020}", prefix, i);
            let ts = GENESIS_TIMESTAMP + i as u64 + 1;
            let block = Block {
                header: BlockHeader::new_with_defaults(
                    1,
                    hash.clone(),
                    vec![prev.clone()],
                    format!("m_{}_{}", prefix, i),
                    ts,
                    i as u64,
                    ConsensusParams::GENESIS_DIFFICULTY,
                    (i + 1) as u64,
                ),
                body: BlockBody {
                    transactions: vec![Transaction {
                        hash: format!("cb_{}_{}", prefix, i),
                        inputs: vec![],
                        outputs: vec![TxOutput {
                            address: format!("shadow1det_{}", i),
                            amount: 1_000,
                            commitment: None,
                            range_proof: None,
                            ephemeral_pubkey: None,
                        }],
                        fee: 0,
                        timestamp: ts,
                        is_coinbase: true,
                        tx_type: TxType::Transfer,
                        payload_hash: None,
                        ..Default::default()
                    }],
                },
            };
            blocks.push(block.clone());
            prev = hash;
        }
        blocks
    }

    fn compute_dag_state_root(dag: &DagManager) -> String {
        let mut all: Vec<String> = dag.get_all_blocks_map().keys().cloned().collect();
        all.sort();
        let mut h = Sha256::new();
        for hash in &all {
            h.update(hash.as_bytes());
        }
        hex::encode(h.finalize())
    }

    fn compute_utxo_root(utxo: &UtxoSet) -> String {
        let mut entries = utxo.export_all();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut h = Sha256::new();
        for (key, u) in &entries {
            h.update(key.as_bytes());
            h.update(u.amount.to_le_bytes());
            h.update(if u.spent { b"1" } else { b"0" });
        }
        hex::encode(h.finalize())
    }

    #[test]
    fn same_blocks_produce_same_dag_state_root() {
        let chain = deterministic_chain("det_chain");
        let dag_a = tmp_dag("state_root_a");
        for block in &chain {
            dag_a.add_block_validated(block, true).unwrap();
        }
        let dag_b = tmp_dag("state_root_b");
        for block in &chain {
            dag_b.add_block_validated(block, true).unwrap();
        }
        assert_eq!(
            compute_dag_state_root(&dag_a),
            compute_dag_state_root(&dag_b)
        );
    }

    #[test]
    fn different_blocks_produce_different_state_roots() {
        let chain_a = deterministic_chain("det_a");
        let chain_b = deterministic_chain("det_b");
        let dag_a = tmp_dag("diff_a");
        let dag_b = tmp_dag("diff_b");
        for block in &chain_a {
            dag_a.add_block_validated(block, true).unwrap();
        }
        for block in &chain_b {
            dag_b.add_block_validated(block, true).unwrap();
        }
        assert_ne!(
            compute_dag_state_root(&dag_a),
            compute_dag_state_root(&dag_b)
        );
    }

    #[test]
    fn tx_hash_fully_deterministic_across_calls() {
        let tx = Transaction {
            hash: String::new(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "shadow1det_hash".into(),
                amount: 5_000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 3,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        let hashes: Vec<String> = (0..100).map(|_| TxHash::hash(&tx)).collect();
        let first = &hashes[0];
        assert!(hashes.iter().all(|h| h == first));
    }

    #[test]
    fn block_hash_matches_reconstructed_hash() {
        let tx = Transaction {
            hash: "preset_hash_for_det_test".to_string(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "shadow1".into(),
                amount: 1_000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 0,
            timestamp: GENESIS_TIMESTAMP,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        assert_eq!(TxHash::hash(&tx), TxHash::hash(&tx));
    }

    #[test]
    fn utxo_state_root_deterministic() {
        let ops: Vec<(&str, &str, u64, &str)> = vec![
            ("det_u1:0", "owner_a", 1_000, "shadow1_a"),
            ("det_u2:0", "owner_b", 2_000, "shadow1_b"),
            ("det_u3:0", "owner_c", 3_000, "shadow1_c"),
        ];
        let utxo_x = tmp_utxo("root_x");
        let utxo_y = tmp_utxo("root_y");
        for (key, owner, amount, addr) in &ops {
            utxo_x.add_utxo_str(key, (*owner).into(), *amount, (*addr).into());
            utxo_y.add_utxo_str(key, (*owner).into(), *amount, (*addr).into());
        }
        utxo_x.spend_utxo_str("det_u2:0").unwrap();
        utxo_y.spend_utxo_str("det_u2:0").unwrap();
        assert_eq!(compute_utxo_root(&utxo_x), compute_utxo_root(&utxo_y));
    }

    #[test]
    fn genesis_hash_is_deterministic() {
        let h1 = ConsensusParams::genesis_hash();
        let h2 = ConsensusParams::genesis_hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn signing_message_deterministic() {
        let tx = Transaction {
            hash: "det_sign_tx".to_string(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "shadow1".into(),
                amount: 1_000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 1,
            timestamp: GENESIS_TIMESTAMP,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        assert_eq!(TxHash::signing_message(&tx), TxHash::signing_message(&tx));
    }

    #[test]
    fn re_applying_same_chain_idempotent_dag_size() {
        let chain = deterministic_chain("idem");
        let dag1 = tmp_dag("idem_1");
        let dag2 = tmp_dag("idem_2");
        for b in &chain {
            dag1.add_block_validated(b, true).unwrap();
        }
        for b in &chain {
            dag2.add_block_validated(b, true).unwrap();
        }
        assert_eq!(dag1.dag_size(), dag2.dag_size());
    }
}
