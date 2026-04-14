// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//         Recovery Tests — crash/restart, state sync, no data loss
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use crate::config::consensus::consensus_params::ConsensusParams;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::domain::transaction::tx_hash::TxHash;
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::engine::dag::core::dag_manager::DagManager;
    use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
    use crate::service::mempool::core::mempool::Mempool;
    use crate::service::network::p2p::peer_manager::PeerManager;
    use std::sync::Arc;

    fn genesis_block() -> Block {
        Block {
            header: BlockHeader::new_with_defaults(
                1,
                "rec_genesis_0000000000000".to_string(),
                vec![],
                "merkle_rec_genesis".to_string(),
                ConsensusParams::GENESIS_TIMESTAMP,
                0,
                ConsensusParams::GENESIS_DIFFICULTY,
                0,
            ),
            body: BlockBody {
                transactions: vec![Transaction {
                    hash: "cb_rec_genesis".to_string(),
                    inputs: vec![],
                    outputs: vec![TxOutput {
                        address: "shadow1rec".into(),
                        amount: 10_000,
                        commitment: None,
                        range_proof: None,
                        ephemeral_pubkey: None,
                    }],
                    fee: 0,
                    timestamp: ConsensusParams::GENESIS_TIMESTAMP,
                    is_coinbase: true,
                    tx_type: TxType::Transfer,
                    payload_hash: None,
                    ..Default::default()
                }],
            },
        }
    }

    fn make_block(hash: &str, parent: &str, height: u64) -> Block {
        let ts = ConsensusParams::GENESIS_TIMESTAMP + height;
        Block {
            header: BlockHeader::new_with_defaults(
                1,
                hash.to_string(),
                vec![parent.to_string()],
                format!("m_{}", hash),
                ts,
                0,
                ConsensusParams::GENESIS_DIFFICULTY,
                height,
            ),
            body: BlockBody {
                transactions: vec![Transaction {
                    hash: format!("cb_{}", hash),
                    inputs: vec![],
                    outputs: vec![TxOutput {
                        address: "shadow1rec".into(),
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
        }
    }

    fn make_coinbase_tx(i: usize) -> Transaction {
        let mut tx = Transaction {
            hash: String::new(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "shadow1rec_addr".into(),
                amount: 1_000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 1,
            timestamp: 1_735_689_600 + i as u64,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        tx.hash = TxHash::hash(&tx);
        tx
    }

    #[test]
    fn dag_state_persists_after_reopen() {
        let path = "/tmp/rec_dag_persist";
        let _ = std::fs::remove_dir_all(path);
        {
            let dag = DagManager::new_required(path).unwrap();
            let g = genesis_block();
            dag.add_block_validated(&g, true).unwrap();
            let b1 = make_block("rec_b1_aaaaaaaaaaaa", &g.header.hash, 1);
            let b2 = make_block("rec_b2_bbbbbbbbbbbb", &b1.header.hash, 2);
            dag.add_block_validated(&b1, true).unwrap();
            dag.add_block_validated(&b2, true).unwrap();
        }
        {
            let dag = DagManager::new_required(path).unwrap();
            assert!(dag.block_exists("rec_genesis_0000000000000"));
            assert!(dag.block_exists("rec_b1_aaaaaaaaaaaa"));
            assert!(dag.block_exists("rec_b2_bbbbbbbbbbbb"));
            assert_eq!(dag.dag_size(), 3);
        }
    }

    #[test]
    fn dag_tips_restored_after_reopen() {
        let path = "/tmp/rec_dag_tips";
        let _ = std::fs::remove_dir_all(path);
        {
            let dag = DagManager::new_required(path).unwrap();
            let g = genesis_block();
            dag.add_block_validated(&g, true).unwrap();
            let b = make_block("rec_tip_ccccccccccc", &g.header.hash, 1);
            dag.add_block_validated(&b, true).unwrap();
        }
        {
            let dag = DagManager::new_required(path).unwrap();
            let tips = dag.get_tips();
            assert!(
                tips.contains(&"rec_tip_ccccccccccc".to_string()),
                "Tip must be restored: {:?}",
                tips
            );
        }
    }

    #[test]
    fn utxo_state_persists_after_reopen() {
        let path = "/tmp/rec_utxo_persist";
        let _ = std::fs::remove_dir_all(path);
        {
            let store = UtxoSet::new(Arc::new(UtxoStore::new(path).expect("open failed")));
            store.add_utxo_str(
                "rec_utxo_tx:0",
                "owner_r".into(),
                9_876,
                "shadow1rec_u".into(),
            );
        }
        {
            let store = UtxoSet::new(Arc::new(UtxoStore::new(path).expect("open failed")));
            let utxo = store.get_utxo_str("rec_utxo_tx:0");
            assert!(utxo.is_some());
            assert_eq!(utxo.unwrap().amount, 9_876);
        }
    }

    #[test]
    fn spent_utxo_state_persists_after_reopen() {
        let path = "/tmp/rec_utxo_spent";
        let _ = std::fs::remove_dir_all(path);
        {
            let store = UtxoSet::new(Arc::new(UtxoStore::new(path).expect("open failed")));
            store.add_utxo_str(
                "rec_spent_tx:0",
                "owner_s".into(),
                5_000,
                "shadow1spent".into(),
            );
            store.spend_utxo_str("rec_spent_tx:0").unwrap();
        }
        {
            let store = UtxoSet::new(Arc::new(UtxoStore::new(path).expect("open failed")));
            let utxo = store.get_utxo_str("rec_spent_tx:0").unwrap();
            assert!(utxo.spent);
        }
    }

    #[test]
    fn mempool_persists_after_reopen() {
        let path = "/tmp/rec_mempool_persist";
        let _ = std::fs::remove_dir_all(path);
        let tx = make_coinbase_tx(42);
        let tx_hash = tx.hash.clone();
        {
            let pool = Mempool::try_new(path).expect("mp");
            pool.add_transaction_test(&tx);
        }
        {
            let pool = Mempool::try_new(path).expect("mp");
            let found = pool.get_transaction(&tx_hash);
            assert!(found.is_some());
        }
    }

    #[test]
    fn peer_manager_persists_after_reopen() {
        let path = "/tmp/rec_pm_persist";
        let _ = std::fs::remove_dir_all(path);
        {
            let pm = PeerManager::new_default_path(path).unwrap();
            pm.add_peer("10.0.0.1:8333").unwrap();
            pm.add_peer("10.0.0.2:8333").unwrap();
        }
        {
            let pm = PeerManager::new_default_path(path).unwrap();
            let peers = pm.get_peers();
            assert!(peers.contains(&"10.0.0.1:8333".to_string()));
            assert!(peers.contains(&"10.0.0.2:8333".to_string()));
        }
    }

    #[test]
    fn ban_persists_after_reopen() {
        let path = "/tmp/rec_pm_ban";
        let _ = std::fs::remove_dir_all(path);
        {
            let pm = PeerManager::new_default_path(path).unwrap();
            pm.ban_peer("192.168.5.5:9000", 7200, "malicious");
        }
        {
            let pm = PeerManager::new_default_path(path).unwrap();
            assert!(pm.is_banned("192.168.5.5:9000"));
        }
    }

    #[test]
    fn multiple_items_no_data_loss_after_reopen() {
        let path = "/tmp/rec_nodataloss";
        let _ = std::fs::remove_dir_all(path);
        let n = 50usize;
        {
            let store = UtxoSet::new(Arc::new(UtxoStore::new(path).expect("open failed")));
            for i in 0..n {
                store.add_utxo_str(
                    &format!("{:064x}:0", i),
                    "owner".into(),
                    (i as u64 + 1) * 100,
                    "shadow1ndl".into(),
                );
            }
        }
        {
            let store = UtxoSet::new(Arc::new(UtxoStore::new(path).expect("open failed")));
            let all = store.export_all();
            assert_eq!(all.len(), n);
        }
    }

    #[test]
    fn dag_parent_relations_persisted() {
        let path = "/tmp/rec_dag_parents";
        let _ = std::fs::remove_dir_all(path);
        {
            let dag = DagManager::new_required(path).unwrap();
            let g = genesis_block();
            dag.add_block_validated(&g, true).unwrap();
            let b = make_block("rec_par_block_ddddddd", &g.header.hash, 1);
            dag.add_block_validated(&b, true).unwrap();
        }
        {
            let dag = DagManager::new_required(path).unwrap();
            let parents = dag.get_parents("rec_par_block_ddddddd");
            assert!(parents.contains(&"rec_genesis_0000000000000".to_string()));
        }
    }

    #[test]
    fn dag_child_relations_persisted() {
        let path = "/tmp/rec_dag_children";
        let _ = std::fs::remove_dir_all(path);
        {
            let dag = DagManager::new_required(path).unwrap();
            let g = genesis_block();
            dag.add_block_validated(&g, true).unwrap();
            let b = make_block("rec_child_block_eeeee", &g.header.hash, 1);
            dag.add_block_validated(&b, true).unwrap();
        }
        {
            let dag = DagManager::new_required(path).unwrap();
            let children = dag.get_children("rec_genesis_0000000000000");
            assert!(children.contains(&"rec_child_block_eeeee".to_string()));
        }
    }
}
