// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//     Performance Tests — TPS, latency, throughput, memory, stress scenarios
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use std::time::Instant;
    use std::sync::Arc;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::domain::transaction::tx_hash::TxHash;
    use crate::domain::transaction::tx_validator::{validate_tx, DUST_LIMIT, MIN_TX_FEE};
    use crate::domain::block::block::Block;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::block::block_body::BlockBody;
    use crate::engine::dag::core::dag_manager::DagManager;
    use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::service::mempool::core::mempool::Mempool;
    use crate::config::consensus::consensus_params::ConsensusParams;

    // ── helpers ──────────────────────────────────────────────────────────
    fn make_coinbase_tx(i: usize) -> Transaction {
        let mut tx = Transaction {
            hash:      String::new(),
            inputs:    vec![],
            outputs:   vec![TxOutput {
                address: format!("shadow1perf_{:020}", i),
                amount:  DUST_LIMIT,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee:       0,
            timestamp: 1_735_689_600 + i as u64,
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
        };
        tx.hash = TxHash::hash(&tx);
        tx
    }

    fn tmp_dag(suffix: &str) -> DagManager {
        let path = format!("/tmp/perf_dag_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        DagManager::new_required(&path).unwrap()
    }

    fn tmp_mempool(suffix: &str) -> Mempool {
        let path = format!("/tmp/perf_mempool_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        Mempool::try_new(path.as_str()).expect("mp")
    }

    fn tmp_utxo(suffix: &str) -> UtxoSet {
        let path = format!("/tmp/perf_utxo_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        UtxoSet::new(Arc::new(UtxoStore::new(path.as_str()).expect("UtxoStore::new failed")))
    }

    fn genesis_block() -> Block {
        Block {
            header: BlockHeader::new_with_defaults(
                1, "perf_genesis_000000000000".to_string(), vec![],
                "merkle_perf_genesis".to_string(),
                ConsensusParams::GENESIS_TIMESTAMP, 0,
                ConsensusParams::GENESIS_DIFFICULTY, 0,
            ),
            body: BlockBody { transactions: vec![Transaction {
                hash: "cb_perf_genesis".to_string(), inputs: vec![],
                outputs: vec![TxOutput { address: "shadow1perf".into(), amount: 10_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
                fee: 0, timestamp: ConsensusParams::GENESIS_TIMESTAMP, is_coinbase: true,
                tx_type: TxType::Transfer,
            payload_hash: None,
            }]},
        }
    }

    #[test]
    fn tx_validation_throughput_10k() {
        let txs: Vec<Transaction> = (0..10_000).map(make_coinbase_tx).collect();
        let start = Instant::now();
        let valid_count = txs.iter().filter(|tx| validate_tx(tx)).count();
        let elapsed = start.elapsed();
        println!("[PERF] 10k TX validation: {} valid in {:.2}ms ({:.0} tx/s)",
            valid_count, elapsed.as_millis(), 10_000.0 / elapsed.as_secs_f64());
        assert!(elapsed.as_secs() < 5);
        assert!(valid_count > 9_000);
    }

    #[test]
    fn tx_hash_throughput_50k() {
        let txs: Vec<Transaction> = (0..50_000)
            .map(|i| Transaction {
                hash: String::new(), inputs: vec![],
                outputs: vec![TxOutput { address: format!("shadow1addr_{}", i), amount: DUST_LIMIT, commitment: None, range_proof: None, ephemeral_pubkey: None }],
                fee: MIN_TX_FEE, timestamp: 1_735_689_600 + i as u64, is_coinbase: false,
                tx_type: TxType::Transfer,
            payload_hash: None,
            }).collect();
        let start = Instant::now();
        let _hashes: Vec<String> = txs.iter().map(TxHash::hash).collect();
        let elapsed = start.elapsed();
        println!("[PERF] 50k TxHash: {:.2}ms", elapsed.as_millis());
        assert!(elapsed.as_secs() < 10);
    }

    #[test]
    fn mempool_insertion_throughput_5k() {
        let pool = tmp_mempool("throughput_5k");
        let txs: Vec<Transaction> = (0..5_000).map(make_coinbase_tx).collect();
        let start = Instant::now();
        let mut accepted = 0usize;
        for tx in &txs { if pool.add_transaction(tx) { accepted += 1; } }
        let elapsed = start.elapsed();
        println!("[PERF] Mempool 5k inserts: {} accepted in {:.2}ms", accepted, elapsed.as_millis());
        assert!(elapsed.as_secs() < 30);
    }

    #[test]
    fn utxo_write_throughput_5k() {
        let store = tmp_utxo("write_5k");
        let start = Instant::now();
        for i in 0..5_000usize {
            store.add_utxo_str(&format!("utxo_perf_{:020}:0", i), "owner".into(), DUST_LIMIT, format!("shadow1perf_{}", i));
        }
        let elapsed = start.elapsed();
        println!("[PERF] utxo 5k writes: {:.2}ms", elapsed.as_millis());
        assert!(elapsed.as_secs() < 30);
    }

    #[test]
    fn utxo_read_throughput_1k_reads() {
        let store = tmp_utxo("read_1k");
        for i in 0..1_000usize {
            store.add_utxo_str(&format!("utxo_read_{:020}:0", i), "owner".into(), DUST_LIMIT, "shadow1read".into());
        }
        let start = Instant::now();
        let mut found = 0usize;
        for i in 0..1_000usize {
            if store.get_utxo_str(&format!("utxo_read_{:020}:0", i)).is_some() { found += 1; }
        }
        let elapsed = start.elapsed();
        println!("[PERF] utxo 1k reads: {} found in {:.2}ms", found, elapsed.as_millis());
        assert_eq!(found, 1_000);
        assert!(elapsed.as_secs() < 10);
    }

    #[test]
    fn dag_insert_1000_blocks_timing() {
        let dag = tmp_dag("timing_1k");
        let g = genesis_block();
        dag.add_block_validated(&g, true).unwrap();
        let mut prev = g.header.hash.clone();
        let start = Instant::now();
        for i in 0..1_000usize {
            let hash = format!("perf_blk_{:020}", i);
            let block = Block {
                header: BlockHeader::new_with_defaults(
                    1, hash.clone(), vec![prev.clone()],
                    format!("m_{}", i), ConsensusParams::GENESIS_TIMESTAMP + i as u64,
                    0, ConsensusParams::GENESIS_DIFFICULTY, (i + 1) as u64,
                ),
                body: BlockBody { transactions: vec![Transaction {
                    hash: format!("cb_perf_{}", i), inputs: vec![],
                    outputs: vec![TxOutput { address: "shadow1".into(), amount: 1_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
                    fee: 0, timestamp: ConsensusParams::GENESIS_TIMESTAMP + i as u64, is_coinbase: true,
                    tx_type: TxType::Transfer,
            payload_hash: None,
                }]},
            };
            dag.add_block_validated(&block, true).unwrap();
            prev = hash;
        }
        let elapsed = start.elapsed();
        println!("[PERF] DAG 1k blocks: {:.2}ms ({:.0} blocks/s)", elapsed.as_millis(), 1_000.0 / elapsed.as_secs_f64());
        assert!(elapsed.as_secs() < 300, "DAG 1k blocks took {}s", elapsed.as_secs());
        assert_eq!(dag.dag_size(), 1_001);
    }

    #[test]
    fn balance_computation_many_utxos() {
        let store = tmp_utxo("balance_many");
        let addr = "shadow1balance_many".to_string();
        for i in 0..500usize {
            store.add_utxo_str(&format!("{:064x}:0", i), "owner".into(), 1_000, addr.clone());
        }
        let start = Instant::now();
        let balance = store.get_balance(&addr);
        let elapsed = start.elapsed();
        println!("[PERF] Balance of 500 utxos: {} in {:.2}ms", balance, elapsed.as_millis());
        assert_eq!(balance, 500_000);
        assert!(elapsed.as_millis() < 5_000);
    }

    #[test]
    fn mempool_select_for_block_from_1000() {
        let pool = tmp_mempool("select_1k");
        for i in 0..1_000usize {
            pool.add_transaction(&make_coinbase_tx(i));
        }
        let utxo_set = crate::domain::utxo::utxo_set::UtxoSet::new_empty();
        let start = Instant::now();
        let selected = pool.get_transactions_for_block(&utxo_set, 500);
        let elapsed = start.elapsed();
        println!("[PERF] Select 500 from 1000: {} selected in {:.2}ms", selected.len(), elapsed.as_millis());
        assert!(selected.len() <= 500);
        assert!(elapsed.as_millis() < 2_000);
    }
}
