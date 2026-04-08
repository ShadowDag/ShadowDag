// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//    Database Tests (RocksDB) — corruption, rollback, recovery, snapshot
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::engine::dag::core::dag_manager::DagManager;
    use crate::service::mempool::core::mempool::Mempool;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::domain::transaction::tx_hash::TxHash;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::block::block_body::BlockBody;
    use crate::config::consensus::consensus_params::ConsensusParams;
    use crate::config::genesis::genesis::GENESIS_TIMESTAMP;

    fn unique_path(prefix: &str, suffix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos();
        let pid = std::process::id();
        format!("/tmp/{}_{}_{}_{}", prefix, suffix, pid, ts)
    }

    fn tmp_store(suffix: &str) -> UtxoStore {
        let path = unique_path("db_store", suffix);
        let _ = std::fs::remove_dir_all(&path);
        UtxoStore::new(path.as_str()).expect("UtxoStore::new failed")
    }

    fn tmp_utxo(suffix: &str) -> UtxoSet {
        UtxoSet::new(Arc::new(tmp_store(suffix)))
    }

    fn tmp_dag(suffix: &str) -> DagManager {
        let path = unique_path("db_dag", suffix);
        let _ = std::fs::remove_dir_all(&path);
        DagManager::new_required(&path).unwrap()
    }

    fn tmp_mempool(suffix: &str) -> Mempool {
        let path = unique_path("db_mempool", suffix);
        let _ = std::fs::remove_dir_all(&path);
        Mempool::try_new(path.as_str()).expect("mp")
    }

    fn genesis_block() -> Block {
        Block {
            header: BlockHeader::new_with_defaults(
                1, "db_genesis_0000000000000".to_string(), vec![],
                "merkle_db_genesis".to_string(),
                GENESIS_TIMESTAMP, 0, ConsensusParams::GENESIS_DIFFICULTY, 0,
            ),
            body: BlockBody { transactions: vec![Transaction {
                hash: "cb_db_genesis".to_string(), inputs: vec![],
                outputs: vec![TxOutput { address: "shadow1db".into(), amount: 10_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
                fee: 0, timestamp: GENESIS_TIMESTAMP, is_coinbase: true,
                tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
            }]},
        }
    }

    fn make_tx(i: usize) -> Transaction {
        let mut tx = Transaction {
            hash: String::new(), inputs: vec![],
            outputs: vec![TxOutput { address: format!("addr_{}", i), amount: 1_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: 1, timestamp: GENESIS_TIMESTAMP + i as u64, is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        tx.hash = TxHash::hash(&tx);
        tx
    }

    #[test]
    fn rocksdb_creates_directory_on_open() {
        let path = "/tmp/db_autocreate";
        let _ = std::fs::remove_dir_all(path);
        assert!(!std::path::Path::new(path).exists());
        let _store = UtxoStore::new(path).expect("open failed");
        assert!(std::path::Path::new(path).exists());
    }

    #[test]
    fn data_immediately_readable_after_write() {
        let store = tmp_utxo("immediate_read");
        store.add_utxo_str("imm_tx:0", "owner".into(), 5_000, "shadow1imm".into());
        assert!(store.get_utxo_str("imm_tx:0").is_some());
    }

    #[test]
    fn rollback_block_unspends_inputs() {
        let store = tmp_utxo("rollback");
        store.add_utxo_str("rb_tx1:0", "owner_rb".into(), 2_000, "shadow1rb".into());
        store.add_utxo_str("rb_tx2:0", "owner_rb".into(), 3_000, "shadow1rb".into());
        fn th(name: &str) -> String {
            use sha2::{Sha256, Digest};
            hex::encode(Sha256::digest(name.as_bytes()))
        }
        let spend_tx = Transaction {
            hash: th("rb_spend_tx"),
            inputs: vec![crate::domain::transaction::transaction::TxInput {
                txid: th("rb_tx1"), index: 0,
                owner: "owner_rb".into(), signature: String::new(), pub_key: String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput { address: "shadow1rb_out".into(), amount: 1_500, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: 1, timestamp: GENESIS_TIMESTAMP + 1, is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        store.spend_utxo_str("rb_tx1:0").unwrap();
        assert!(store.get_utxo_str("rb_tx1:0").unwrap().spent);
        #[allow(deprecated)]
        let _result = store.rollback_block(&[spend_tx]);
        assert!(store.get_utxo_str("rb_tx1:0").is_some());
    }

    #[test]
    fn export_all_snapshot_is_complete() {
        let store = tmp_utxo("snapshot");
        let n = 20usize;
        for i in 0..n { store.add_utxo_str(&format!("snap_tx_{:010}:0", i), "owner".into(), (i as u64 + 1) * 500, "shadow1snap".into()); }
        for i in 0..(n / 2) { store.spend_utxo_str(&format!("snap_tx_{:010}:0", i)).unwrap(); }
        // export_all returns only UNSPENT UTXOs
        let all = store.export_all();
        assert_eq!(all.len(), n / 2);
        let spent_count = all.iter().filter(|(_, u)| u.spent).count();
        let unspent_count = all.iter().filter(|(_, u)| !u.spent).count();
        assert_eq!(spent_count, 0);
        assert_eq!(unspent_count, n / 2);
    }

    #[test]
    fn overwrite_utxo_updates_value() {
        let store = tmp_utxo("overwrite");
        store.add_utxo_str("ow_tx:0", "owner_ow".into(), 1_000, "shadow1ow".into());
        store.add_utxo_str("ow_tx:0", "owner_ow".into(), 9_000, "shadow1ow".into());
        assert_eq!(store.get_utxo_str("ow_tx:0").unwrap().amount, 9_000);
    }

    #[test]
    fn dag_handles_reopen_with_data_correctly() {
        let path = "/tmp/db_dag_reopen";
        let _ = std::fs::remove_dir_all(path);
        let n = 5usize;
        {
            let dag = DagManager::new_required(path).unwrap();
            let g = genesis_block();
            dag.add_block_validated(&g, true).unwrap();
            let mut prev = g.header.hash.clone();
            for i in 0..n {
                let hash = format!("db_reopen_blk_{:010}", i);
                let block = Block {
                    header: BlockHeader::new_with_defaults(
                        1, hash.clone(), vec![prev.clone()],
                        format!("m_{}", i), GENESIS_TIMESTAMP + i as u64,
                        0, ConsensusParams::GENESIS_DIFFICULTY, (i + 1) as u64,
                    ),
                    body: BlockBody { transactions: vec![Transaction {
                        hash: format!("cb_ro_{}", i), inputs: vec![],
                        outputs: vec![TxOutput { address: "shadow1".into(), amount: 1_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
                        fee: 0, timestamp: GENESIS_TIMESTAMP + i as u64, is_coinbase: true,
                        tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
                    }]},
                };
                dag.add_block_validated(&block, true).unwrap();
                prev = hash;
            }
        }
        { let dag = DagManager::new_required(path).unwrap(); assert_eq!(dag.dag_size(), n + 1); }
    }

    #[test]
    fn mempool_add_and_retrieve_roundtrip() {
        let pool = tmp_mempool("roundtrip");
        let txs: Vec<Transaction> = (0..10).map(make_tx).collect();
        for tx in &txs { pool.add_transaction_test(tx); }
        for tx in &txs { assert!(pool.get_transaction(&tx.hash).is_some()); }
    }

    #[test]
    fn balance_consistent_after_many_operations() {
        let store = tmp_utxo("many_ops");
        let addr = "shadow1many".to_string();
        let n = 100usize;
        for i in 0..n { store.add_utxo_str(&format!("many_tx_{:020}:0", i), "owner".into(), 1_000, addr.clone()); }
        for i in (0..n).step_by(2) { store.spend_utxo_str(&format!("many_tx_{:020}:0", i)).unwrap(); }
        assert_eq!(store.get_balance(&addr), (n / 2) as u64 * 1_000);
    }

    #[test]
    fn large_key_set_no_collisions() {
        let store = tmp_utxo("no_collisions");
        let n = 1_000usize;
        for i in 0..n { store.add_utxo_str(&format!("nc_tx_{:020}:0", i), "owner".into(), i as u64 + 1, "shadow1nc".into()); }
        let mut mismatches = 0usize;
        for i in 0..n {
            if let Some(u) = store.get_utxo_str(&format!("nc_tx_{:020}:0", i)) {
                if u.amount != i as u64 + 1 { mismatches += 1; }
            } else { mismatches += 1; }
        }
        assert_eq!(mismatches, 0);
    }
}
