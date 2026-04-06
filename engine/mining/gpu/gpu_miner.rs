// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::domain::block::block::Block;
use crate::engine::mining::algorithms::shadowhash::shadow_hash;
use crate::engine::mining::pow::pow_validator::PowValidator;

pub struct MineResult {
    pub nonce:     u64,
    pub hash:      String,
    pub hashrate:  f64,
    pub time_ms:   u128,
}

pub struct GpuMiner {
    pub device_id:    u32,
    pub difficulty:   u64,
    pub hashrate:     f64,
    pub threads:      usize,
    pub batch_size:   u64,
}

impl GpuMiner {
    pub fn new(device_id: u32, difficulty: u64) -> Self {
        let threads = rayon::current_num_threads();
        eprintln!(
            "GpuMiner → device={} difficulty={} threads={}",
            device_id, difficulty, threads
        );
        Self {
            device_id,
            difficulty,
            hashrate: 0.0,
            threads,
            batch_size: 1_000_000,
        }
    }

    pub fn initialize(&self) {
        eprintln!(
            "GpuMiner → initializing device={} threads={} batch={}",
            self.device_id, self.threads, self.batch_size
        );

        rayon::ThreadPoolBuilder::new()
            .num_threads(self.threads)
            .build_global()
            .ok();
        eprintln!("GpuMiner → thread pool ready");
    }

    pub fn mine(&mut self, mut block: Block) -> Option<Block> {
        eprintln!(
            "GpuMiner → mining block height={} difficulty={} on {} threads",
            block.header.height, self.difficulty, self.threads
        );

        let start    = Instant::now();
        let found    = Arc::new(AtomicBool::new(false));
        let found_nonce = Arc::new(AtomicU64::new(0));
        let hash_count = Arc::new(AtomicU64::new(0));
        let _found_hash = Arc::new(std::sync::Mutex::new(String::new()));

        let difficulty = self.difficulty;
        let total_nonces: u64 = u64::MAX;
        let batch    = self.batch_size;
        let num_batches = total_nonces / batch;

        let t_hash_count = hash_count.clone();
        let result: Option<(u64, String)> = (0..num_batches)
            .into_par_iter()
            .find_map_any(|batch_idx| {
                if found.load(Ordering::Relaxed) {
                    return None;
                }

                let start_nonce = match batch_idx.checked_mul(batch) {
                    Some(n) => n,
                    None => break, // nonce space exhausted
                };
                let end_nonce   = start_nonce.saturating_add(batch);
                let mut local_count: u64 = 0;

                for nonce in start_nonce..end_nonce {
                    if found.load(Ordering::Relaxed) {
                        t_hash_count.fetch_add(local_count, Ordering::Relaxed);
                        return None;
                    }

                    local_count += 1;
                    let mut test_block = block.clone();
                    test_block.header.nonce = nonce;
                    let hash = shadow_hash(&test_block);

                    if PowValidator::hash_meets_target(&hash, difficulty) {
                        found.store(true, Ordering::Relaxed);
                        found_nonce.store(nonce, Ordering::Relaxed);
                        t_hash_count.fetch_add(local_count, Ordering::Relaxed);
                        return Some((nonce, hash));
                    }
                }
                t_hash_count.fetch_add(local_count, Ordering::Relaxed);
                None
            });

        let elapsed_ms = start.elapsed().as_millis();

        if let Some((nonce, hash)) = result {
            let hashes_tried = hash_count.load(Ordering::Relaxed);
            self.hashrate = if elapsed_ms > 0 {
                (hashes_tried as f64 / elapsed_ms as f64) / 1000.0
            } else { 0.0 };

            block.header.nonce = nonce;
            block.header.hash  = hash.clone();

            eprintln!(
                "GpuMiner → ✅ block FOUND! nonce={} hash={}... time={}ms hashrate={:.2}MH/s",
                nonce, &hash[..16], elapsed_ms, self.hashrate
            );
            Some(block)
        } else {
            eprintln!("GpuMiner → no valid nonce found in search range");
            None
        }
    }

    pub fn mine_with_callback<F>(&mut self, block: Block, on_hashrate: F) -> Option<Block>
    where
        F: Fn(f64) + Send + Sync,
    {
        let result = self.mine(block);
        on_hashrate(self.hashrate);
        result
    }

    pub fn benchmark(&mut self) -> f64 {
        use crate::config::genesis::genesis::create_genesis_block;
        let block   = create_genesis_block();
        let start   = Instant::now();
        let iters   = 100_000u64;

        let count: u64 = (0..iters).into_par_iter().filter(|&nonce| {
            let mut b = block.clone();
            b.header.nonce = nonce;
            let h = shadow_hash(&b);
            PowValidator::hash_meets_target(&h, 1)
        }).count() as u64;

        let elapsed_ms = start.elapsed().as_millis().max(1);
        self.hashrate  = (iters as f64 / elapsed_ms as f64) / 1000.0;

        eprintln!(
            "GpuMiner → benchmark: {:.2} MH/s ({} hashes in {}ms, {} valid)",
            self.hashrate, iters, elapsed_ms, count
        );
        self.hashrate
    }

    pub fn stop(&self) {
        eprintln!("GpuMiner → stopped device {}", self.device_id);
    }

    pub fn available_threads() -> usize {
        rayon::current_num_threads()
    }
}
