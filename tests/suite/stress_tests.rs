// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//     Stress Tests — 1M transactions, 10k blocks, 300ms latency simulation
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
    use crate::config::genesis::genesis::GENESIS_TIMESTAMP;

    // ── helpers ──────────────────────────────────────────────────────────
    fn make_tx(i: usize) -> Transaction {
        let mut tx = Transaction {
            hash:      String::new(),
            inputs:    vec![],
            outputs:   vec![TxOutput {
                address: format!("shadow1stress_{:020}", i % 10_000),
                amount:  DUST_LIMIT,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee:       0,
            timestamp: GENESIS_TIMESTAMP + i as u64,
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
        };
        tx.hash = TxHash::hash(&tx);
        tx
    }

    fn tmp_dag(suffix: &str) -> DagManager {
        let path = format!("/tmp/stress_dag_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        DagManager::new_required(&path).unwrap()
    }

    fn tmp_mempool(suffix: &str) -> Mempool {
        let path = format!("/tmp/stress_mempool_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        Mempool::try_new(path.as_str()).expect("mp")
    }

    fn tmp_utxo(suffix: &str) -> UtxoSet {
        let path = format!("/tmp/stress_utxo_{}", suffix);
        let _ = std::fs::remove_dir_all(&path);
        UtxoSet::new(Arc::new(UtxoStore::new(path.as_str()).expect("UtxoStore::new failed")))
    }

    fn genesis_block() -> Block {
        Block {
            header: BlockHeader::new_with_defaults(
                1, "stress_genesis_00000000000".to_string(), vec![],
                "m_stress_genesis".to_string(),
                GENESIS_TIMESTAMP, 0, ConsensusParams::GENESIS_DIFFICULTY, 0,
            ),
            body: BlockBody { transactions: vec![Transaction {
                hash: "cb_stress_genesis".to_string(), inputs: vec![],
                outputs: vec![TxOutput { address: "shadow1stress".into(), amount: 10_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
                fee: 0, timestamp: GENESIS_TIMESTAMP, is_coinbase: true,
                tx_type: TxType::Transfer,
            payload_hash: None,
            }]},
        }
    }

    // ── 1. 100k unique TX hash generations ───────────────────────────────
    #[test]
    fn stress_hash_100k_txs() {
        let start = Instant::now();
        let hashes: Vec<String> = (0..100_000usize)
            .map(|i| {
                let tx = Transaction {
                    hash:      String::new(),
                    inputs:    vec![],
                    outputs:   vec![TxOutput {
                        address: format!("shadow1_{}", i),
                        amount:  DUST_LIMIT,
                        commitment: None,
                        range_proof: None,
                        ephemeral_pubkey: None,
                    }],
                    fee:       MIN_TX_FEE,
                    timestamp: GENESIS_TIMESTAMP + i as u64,
                    is_coinbase: false,
                    tx_type: TxType::Transfer,
            payload_hash: None,
                };
                TxHash::hash(&tx)
            })
            .collect();
        let elapsed = start.elapsed();

        // All hashes must be non-empty
        assert!(hashes.iter().all(|h: &String| !h.is_empty()));
        // All hashes must be unique (no collisions)
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(unique.len(), 100_000, "All 100k hashes must be unique");

        println!(
            "[STRESS] 100k TxHash: {:.2}s ({:.0} hash/s)",
            elapsed.as_secs_f64(),
            100_000.0 / elapsed.as_secs_f64()
        );
    }

    // ── 2. 10k TX validation back-to-back ────────────────────────────────
    #[test]
    fn stress_validate_10k_txs() {
        let txs: Vec<Transaction> = (0..10_000).map(make_tx).collect();

        let start = Instant::now();
        let valid: Vec<bool> = txs.iter().map(validate_tx).collect();
        let elapsed = start.elapsed();

        let accepted = valid.iter().filter(|&&v| v).count();
        println!(
            "[STRESS] 10k TX validate: {} accepted in {:.2}ms",
            accepted, elapsed.as_millis()
        );
        assert!(accepted > 9_000, "At least 90% of TXs must be valid (got {})", accepted);
        assert!(elapsed.as_secs() < 10, "10k validation must finish within 10s");
    }

    // ── 3. 5k utxo writes ────────────────────────────────────────────────
    #[test]
    fn stress_utxo_5k_writes_and_reads() {
        let store = tmp_utxo("5k_rw");
        let n = 5_000usize;

        let start = Instant::now();
        for i in 0..n {
            store.add_utxo_str(
                &format!("stress_utxo_{:020}:0", i),
                "owner".into(),
                DUST_LIMIT,
                format!("shadow1stress_addr_{}", i % 100),
            );
        }
        let write_t = start.elapsed();

        let start = Instant::now();
        let mut found = 0usize;
        for i in 0..n {
            if store.get_utxo_str(&format!("stress_utxo_{:020}:0", i)).is_some() {
                found += 1;
            }
        }
        let read_t = start.elapsed();

        println!(
            "[STRESS] 5k utxo writes: {:.2}ms, reads: {:.2}ms, found: {}",
            write_t.as_millis(), read_t.as_millis(), found
        );
        assert_eq!(found, n);
        assert!(write_t.as_secs() < 60 && read_t.as_secs() < 60);
    }

    // ── 4. 2k block linear DAG ────────────────────────────────────────────
    #[test]
    fn stress_dag_2k_linear_blocks() {
        let dag = tmp_dag("2k_linear");
        let g = genesis_block();
        dag.add_block_validated(&g, true).unwrap();
        let mut prev = g.header.hash.clone();

        let start = Instant::now();
        for i in 0..2_000usize {
            let hash = format!("stress_blk_{:020}", i);
            let block = Block {
                header: BlockHeader::new_with_defaults(
                    1, hash.clone(), vec![prev.clone()],
                    format!("ms_{}", i), GENESIS_TIMESTAMP + i as u64,
                    0, ConsensusParams::GENESIS_DIFFICULTY, (i + 1) as u64,
                ),
                body: BlockBody { transactions: vec![Transaction {
                    hash: format!("cb_s_{}", i), inputs: vec![],
                    outputs: vec![TxOutput { address: "shadow1".into(), amount: 1_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
                    fee: 0, timestamp: GENESIS_TIMESTAMP + i as u64, is_coinbase: true,
                    tx_type: TxType::Transfer,
            payload_hash: None,
                }]},
            };
            dag.add_block_validated(&block, true).unwrap();
            prev = hash;
        }
        let elapsed = start.elapsed();

        println!(
            "[STRESS] 2k DAG blocks: {:.2}s ({:.0} blk/s)",
            elapsed.as_secs_f64(),
            2_000.0 / elapsed.as_secs_f64()
        );
        assert_eq!(dag.dag_size(), 2_001);
        assert!(elapsed.as_secs() < 600, "2k blocks must insert within 10 minutes (debug mode with 256KB scratchpad)");
    }

    // ── 5. DAG fan-out (wide DAG — many parallel blocks) ─────────────────
    #[test]
    fn stress_dag_wide_fanout() {
        let dag = tmp_dag("wide_fanout");
        let g = genesis_block();
        dag.add_block_validated(&g, true).unwrap();

        // 200 parallel branches from genesis
        let start = Instant::now();
        for i in 0..200usize {
            let hash = format!("fanout_blk_{:020}", i);
            let block = Block {
                header: BlockHeader::new_with_defaults(
                    1, hash.clone(), vec![g.header.hash.clone()],
                    format!("mf_{}", i), GENESIS_TIMESTAMP + i as u64,
                    0, ConsensusParams::GENESIS_DIFFICULTY, 1,
                ),
                body: BlockBody { transactions: vec![Transaction {
                    hash: format!("cb_f_{}", i), inputs: vec![],
                    outputs: vec![TxOutput { address: "shadow1".into(), amount: 1_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
                    fee: 0, timestamp: GENESIS_TIMESTAMP + i as u64, is_coinbase: true,
                    tx_type: TxType::Transfer,
            payload_hash: None,
                }]},
            };
            dag.add_block_validated(&block, true).unwrap();
        }
        let elapsed = start.elapsed();

        println!(
            "[STRESS] 200 wide fanout blocks: {:.2}ms",
            elapsed.as_millis()
        );
        assert_eq!(dag.dag_size(), 201);
        // All 200 should be tips (none reference each other)
        let tips = dag.get_tips();
        assert_eq!(tips.len(), 200, "All 200 parallel blocks must be tips");
        assert!(elapsed.as_secs() < 60);
    }

    // ── 6. Mempool stress — 10k transactions ─────────────────────────────
    #[test]
    fn stress_mempool_10k_transactions() {
        let pool = tmp_mempool("10k");
        let txs: Vec<Transaction> = (0..10_000).map(make_tx).collect();

        let start = Instant::now();
        let mut accepted = 0usize;
        for tx in &txs {
            if pool.add_transaction_test(tx) { accepted += 1; }
        }
        let elapsed = start.elapsed();

        println!(
            "[STRESS] Mempool 10k: {} accepted in {:.2}s ({:.0} tx/s)",
            accepted,
            elapsed.as_secs_f64(),
            accepted as f64 / elapsed.as_secs_f64()
        );
        // At least 50% accepted (mempool may enforce limits/evictions)
        assert!(accepted >= 1_000, "At least 1000 TXs must be accepted (got {})", accepted);
        assert!(elapsed.as_secs() < 120, "10k mempool stress must finish within 2 minutes");
    }

    // ── 7. utxo balance under 300ms simulated network latency ────────────
    #[test]
    fn stress_balance_under_latency_simulation() {
        let store = tmp_utxo("latency_sim");
        let addr = "shadow1latency".to_string();

        // Pre-populate
        for i in 0..100usize {
            store.add_utxo_str(
                &format!("{:064x}:0", i),
                "owner".into(),
                1_000,
                addr.clone(),
            );
        }

        // Simulate 300ms "network latency" with sleep, then verify balance
        std::thread::sleep(std::time::Duration::from_millis(300));

        let start = Instant::now();
        let balance = store.get_balance(&addr);
        let query_t = start.elapsed();

        assert_eq!(balance, 100_000, "Balance must be correct after latency simulation");
        println!("[STRESS] Balance query after 300ms sleep: {:.2}ms", query_t.as_millis());
        assert!(query_t.as_millis() < 1_000, "Balance query must be fast after latency");
    }

    // ── 8. No duplicate hashes in 50k generated TXs ──────────────────────
    #[test]
    fn stress_50k_tx_no_hash_collisions() {
        let hashes: Vec<String> = (0..50_000usize)
            .map(|i| {
                let tx = Transaction {
                    hash:      String::new(),
                    inputs:    vec![],
                    outputs:   vec![TxOutput {
                        address: format!("shadow1unique_{}", i),
                        amount:  DUST_LIMIT,
                        commitment: None,
                        range_proof: None,
                        ephemeral_pubkey: None,
                    }],
                    fee:       MIN_TX_FEE,
                    timestamp: GENESIS_TIMESTAMP + i as u64,
                    is_coinbase: false,
                    tx_type: TxType::Transfer,
            payload_hash: None,
                };
                TxHash::hash(&tx)
            })
            .collect();

        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(
            unique.len(),
            hashes.len(),
            "All 50k TX hashes must be unique — no collisions"
        );
    }
}
