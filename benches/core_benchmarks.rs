// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Core Benchmarks — Measures performance of consensus-critical operations.
//
// Run: cargo bench
// ═══════════════════════════════════════════════════════════════════════════

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use shadowdag::config::consensus::emission_schedule::EmissionSchedule;
use shadowdag::domain::block::merkle_tree::MerkleTree;
use shadowdag::domain::transaction::transaction::Transaction;
use shadowdag::engine::consensus::difficulty::difficulty::Difficulty;
use shadowdag::engine::dag::core::bps_engine::BpsParams;
use shadowdag::engine::mining::algorithms::shadowhash::{shadow_hash_raw_full, shadow_hash_str};
use shadowdag::engine::mining::pow::pow_validator::PowValidator;

fn bench_shadowhash(c: &mut Criterion) {
    c.bench_function("shadowhash_raw", |b| {
        b.iter(|| {
            shadow_hash_raw_full(
                black_box(1),
                black_box(100),
                black_box(1735689600),
                black_box(42),
                black_box(0),
                black_box(4),
                black_box("merkle_root_hash"),
                black_box(&[]),
            )
        })
    });
}

fn bench_shadowhash_str(c: &mut Criterion) {
    c.bench_function("shadowhash_str", |b| {
        b.iter(|| shadow_hash_str(black_box("test_data_for_hashing")))
    });
}

fn bench_hash_meets_target(c: &mut Criterion) {
    let hash = "0000ffff00000000000000000000000000000000000000000000000000000000";
    c.bench_function("hash_meets_target", |b| {
        b.iter(|| PowValidator::hash_meets_target(black_box(hash), black_box(4)))
    });
}

fn bench_difficulty_to_target(c: &mut Criterion) {
    c.bench_function("difficulty_to_target", |b| {
        b.iter(|| PowValidator::difficulty_to_target(black_box(1000)))
    });
}

fn bench_difficulty_adjust(c: &mut Criterion) {
    c.bench_function("difficulty_adjust", |b| {
        b.iter(|| Difficulty::adjust(black_box(1000), black_box(950), black_box(100)))
    });
}

fn bench_bps_params(c: &mut Criterion) {
    c.bench_function("bps_params_for_32", |b| {
        b.iter(|| BpsParams::for_bps(black_box(32)))
    });
}

fn bench_emission_reward(c: &mut Criterion) {
    c.bench_function("emission_block_reward", |b| {
        b.iter(|| EmissionSchedule::block_reward(black_box(1_000_000)))
    });
}

fn bench_merkle_tree_100(c: &mut Criterion) {
    let hashes: Vec<String> = (0..100).map(|i| format!("{:064x}", i)).collect();
    let txs: Vec<Transaction> = hashes
        .into_iter()
        .map(|hash| Transaction {
            hash,
            ..Transaction::default()
        })
        .collect();
    c.bench_function("merkle_tree_100_txs", |b| {
        b.iter(|| MerkleTree::build(black_box(&txs), black_box(1), black_box(&[])))
    });
}

fn bench_merkle_tree_1000(c: &mut Criterion) {
    let hashes: Vec<String> = (0..1000).map(|i| format!("{:064x}", i)).collect();
    let txs: Vec<Transaction> = hashes
        .into_iter()
        .map(|hash| Transaction {
            hash,
            ..Transaction::default()
        })
        .collect();
    c.bench_function("merkle_tree_1000_txs", |b| {
        b.iter(|| MerkleTree::build(black_box(&txs), black_box(1), black_box(&[])))
    });
}

fn bench_merkle_proof(c: &mut Criterion) {
    let hashes: Vec<String> = (0..1000).map(|i| format!("{:064x}", i)).collect();
    c.bench_function("merkle_proof_generate_1000", |b| {
        b.iter(|| MerkleTree::generate_proof(black_box(&hashes), black_box(500)))
    });
}

fn bench_blue_work(c: &mut Criterion) {
    c.bench_function("blue_work_accumulate", |b| {
        b.iter(|| Difficulty::accumulate_blue_work(black_box(1_000_000u128), black_box(5000)))
    });
}

fn bench_past_median_time(c: &mut Criterion) {
    let timestamps: Vec<u64> = (0..263).map(|i| 1735689600 + i * 100).collect();
    c.bench_function("past_median_time_263", |b| {
        b.iter(|| Difficulty::past_median_time(black_box(&timestamps)))
    });
}

criterion_group!(
    benches,
    bench_shadowhash,
    bench_shadowhash_str,
    bench_hash_meets_target,
    bench_difficulty_to_target,
    bench_difficulty_adjust,
    bench_bps_params,
    bench_emission_reward,
    bench_merkle_tree_100,
    bench_merkle_tree_1000,
    bench_merkle_proof,
    bench_blue_work,
    bench_past_median_time,
);
criterion_main!(benches);
