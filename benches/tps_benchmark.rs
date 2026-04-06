// TPS Benchmark — Measures transaction processing throughput.
//
// Run: cargo bench --bench tps_benchmark

use criterion::{criterion_group, criterion_main, Criterion, black_box, BenchmarkId};
use std::time::Instant;

use shadowdag::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
use shadowdag::domain::transaction::tx_validator;
use shadowdag::domain::block::merkle_tree::MerkleTree;

/// Generate a realistic-looking transaction for benchmarking.
fn make_bench_tx(i: u64) -> Transaction {
    let hash = format!("{:064x}", i);
    Transaction {
        hash: hash.clone(),
        inputs: vec![TxInput::new(
            format!("{:064x}", i.wrapping_add(1000)),
            0,
            format!("SD1{:040x}", i),
            "a".repeat(128),
            "b".repeat(64),
        )],
        outputs: vec![
            TxOutput::new(format!("SD1{:040x}", i + 1), 50_000_000),
            TxOutput::new(format!("SD1{:040x}", i + 2), 49_000_000),
        ],
        fee: 1_000_000,
        timestamp: 1700000000 + i,
        is_coinbase: false,
        tx_type: TxType::Transfer,
        payload_hash: None,
    }
}

fn bench_tx_creation(c: &mut Criterion) {
    c.bench_function("tx_creation_1000", |b| {
        b.iter(|| {
            let txs: Vec<Transaction> = (0..1000).map(|i| make_bench_tx(black_box(i))).collect();
            black_box(txs);
        })
    });
}

fn bench_tx_structural_validation(c: &mut Criterion) {
    let txs: Vec<Transaction> = (0..1000).map(make_bench_tx).collect();

    c.bench_function("tx_structural_validation_1000", |b| {
        b.iter(|| {
            for tx in &txs {
                black_box(tx_validator::validate_tx(tx));
            }
        })
    });
}

fn bench_tx_hash_computation(c: &mut Criterion) {
    let txs: Vec<Transaction> = (0..1000).map(make_bench_tx).collect();

    c.bench_function("tx_canonical_bytes_1000", |b| {
        b.iter(|| {
            for tx in &txs {
                black_box(tx.canonical_bytes());
            }
        })
    });
}

fn bench_merkle_tree_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree");
    for size in [100, 500, 1000, 2000] {
        let txs: Vec<Transaction> = (0..size).map(|i| make_bench_tx(i as u64)).collect();
        group.bench_with_input(BenchmarkId::from_parameter(size), &txs, |b, txs| {
            b.iter(|| {
                black_box(MerkleTree::build(txs, 1, &["parent".to_string()]));
            })
        });
    }
    group.finish();
}

fn bench_tps_throughput(c: &mut Criterion) {
    // Measures raw TPS: how many TXs can be structurally validated per second
    let txs: Vec<Transaction> = (0..10_000).map(make_bench_tx).collect();

    c.bench_function("tps_structural_10k", |b| {
        b.iter(|| {
            let start = Instant::now();
            let mut count = 0u64;
            for tx in &txs {
                if tx_validator::validate_tx(tx) {
                    count += 1;
                }
            }
            let elapsed = start.elapsed().as_secs_f64();
            let tps = count as f64 / elapsed;
            black_box(tps);
        })
    });
}

criterion_group!(
    benches,
    bench_tx_creation,
    bench_tx_structural_validation,
    bench_tx_hash_computation,
    bench_merkle_tree_scaling,
    bench_tps_throughput,
);
criterion_main!(benches);
