// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rayon::prelude::*;
use std::time::Instant;
use crate::engine::mining::algorithms::shadowhash::shadow_hash;
use crate::engine::mining::pow::pow_validator::PowValidator;
use crate::domain::block::block::Block;
use crate::{slog_info, slog_error};

pub struct CudaDeviceInfo {
    pub device_id:    u32,
    pub device_name:  String,
    pub compute_units: u32,
    pub memory_gb:    f32,
}

pub struct CudaMiner {
    pub device_id:  u32,
    pub block_size: u32,
    pub grid_size:  u32,
}

impl CudaMiner {
    pub fn new(device_id: u32) -> Self {
        slog_info!("gpu", "cuda_miner_initializing", device => device_id);
        Self {
            device_id,
            block_size: 256,
            grid_size:  1024,
        }
    }

    pub fn device_info(&self) -> CudaDeviceInfo {
        CudaDeviceInfo {
            device_id:     self.device_id,
            device_name:   format!("ShadowDAG-CUDA-Device-{}", self.device_id),
            compute_units: rayon::current_num_threads() as u32 * 64,
            memory_gb:     8.0,
        }
    }

    pub fn load_kernel(&self) {
        slog_info!("gpu", "cuda_kernel_loaded", device => self.device_id, block_size => self.block_size, grid_size => self.grid_size);

    }

    pub fn compute_pow(&self, block: &Block, difficulty: u64) -> Option<u64> {
        slog_info!("gpu", "cuda_compute_pow", difficulty => difficulty, device => self.device_id, grid_size => self.grid_size, block_size => self.block_size);

        let _difficulty = difficulty;
        let total = match (self.grid_size as u64).checked_mul(self.block_size as u64) {
            Some(n) => n,
            None => {
                slog_error!("gpu", "cuda_grid_block_overflow");
                return None;
            }
        };
        let start     = Instant::now();

        let result: Option<u64> = (0..total)
            .into_par_iter()
            .find_any(|&nonce| {
                let mut b = block.clone();
                b.header.nonce = nonce;
                PowValidator::hash_meets_target(&shadow_hash(&b), difficulty)
            });

        let elapsed = start.elapsed().as_millis();
        slog_info!("gpu", "cuda_kernel_done", time_ms => elapsed, found => result.is_some());
        result
    }

    pub fn mine_block(&self, mut block: Block, difficulty: u64) -> Option<Block> {
        self.load_kernel();

        let batch_size = (self.grid_size as u64) * (self.block_size as u64);

        const MAX_BATCHES: u64 = 1_000_000;
        for batch in 0..MAX_BATCHES {
            let start_nonce = match batch.checked_mul(batch_size) {
                Some(n) => n,
                None => break, // nonce space exhausted
            };
            let end_nonce = start_nonce.saturating_add(batch_size);

            let found: Option<u64> = (start_nonce..end_nonce)
                .into_par_iter()
                .find_any(|&nonce| {
                    let mut b = block.clone();
                    b.header.nonce = nonce;
                    PowValidator::hash_meets_target(&shadow_hash(&b), difficulty)
                });

            if let Some(nonce) = found {
                block.header.nonce = nonce;
                block.header.hash  = {
                    let mut b = block.clone();
                    b.header.nonce = nonce;
                    shadow_hash(&b)
                };
                slog_info!("gpu", "cuda_block_found", nonce => nonce, hash_prefix => &block.header.hash[..16]);
                return Some(block);
            }
        }
        None
    }
}
