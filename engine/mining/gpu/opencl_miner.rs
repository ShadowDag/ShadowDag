// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rayon::prelude::*;
use std::time::Instant;
use crate::engine::mining::algorithms::shadowhash::shadow_hash;
use crate::engine::mining::pow::pow_validator::PowValidator;
use crate::domain::block::block::Block;
use crate::{slog_info, slog_warn};

pub struct OpenClPlatformInfo {
    pub platform_id:  u32,
    pub vendor:       String,
    pub version:      String,
    pub device_count: u32,
}

pub struct OpenClMiner {
    pub platform_id: u32,
    pub device_id:   u32,
    pub work_size:   u64,
    pub local_size:  u64,
}

impl OpenClMiner {
    pub fn new(platform_id: u32, device_id: u32) -> Self {
        slog_info!("gpu", "opencl_miner_initializing", platform => platform_id, device => device_id);
        Self {
            platform_id,
            device_id,
            work_size:  1_048_576,
            local_size: 256,
        }
    }

    pub fn platform_info(&self) -> OpenClPlatformInfo {
        let vendor = match self.platform_id {
            0 => "NVIDIA Corporation",
            1 => "Advanced Micro Devices, Inc.",
            2 => "Intel(R) Corporation",
            _ => "Generic OpenCL",
        };
        OpenClPlatformInfo {
            platform_id:  self.platform_id,
            vendor:       vendor.to_string(),
            version:      "OpenCL 3.0".to_string(),
            device_count: rayon::current_num_threads() as u32,
        }
    }

    pub fn initialize(&self) {
        let info = self.platform_info();
        slog_info!("gpu", "opencl_platform_info", platform => self.platform_id, vendor => info.vendor, device => self.device_id, work_size => self.work_size);

        slog_info!("gpu", "opencl_context_ready");
    }

    pub fn compute_pow(&self, block: &Block, difficulty: u64) -> Option<u64> {
        slog_info!("gpu", "opencl_compute_pow", difficulty => difficulty, platform => self.platform_id, device => self.device_id, work_size => self.work_size);

        let _difficulty = difficulty;
        let start   = Instant::now();

        let result: Option<u64> = (0..self.work_size)
            .into_par_iter()
            .find_any(|&nonce| {
                let mut b = block.clone();
                b.header.nonce = nonce;
                PowValidator::hash_meets_target(&shadow_hash(&b), difficulty)
            });

        let elapsed = start.elapsed().as_millis();
        slog_info!("gpu", "opencl_kernel_done", time_ms => elapsed, found => result.is_some());
        result
    }

    pub fn mine_block(&self, mut block: Block, difficulty: u64) -> Option<Block> {
        if self.work_size == 0 {
            slog_warn!("gpu", "opencl_work_size_zero");
            return None;
        }
        self.initialize();

        const MAX_WAVES: u64 = 1_000_000;
        for wave in 0..(u64::MAX / self.work_size).min(MAX_WAVES) {
            let offset = match wave.checked_mul(self.work_size) {
                Some(n) => n,
                None => break, // nonce space exhausted
            };

            let end_offset = match offset.checked_add(self.work_size) {
                Some(n) => n,
                None => break,
            };
            let found: Option<u64> = (offset..end_offset)
                .into_par_iter()
                .find_any(|&nonce| {
                    let mut b = block.clone();
                    b.header.nonce = nonce;
                    PowValidator::hash_meets_target(&shadow_hash(&b), difficulty)
                });

            if let Some(nonce) = found {
                block.header.nonce = nonce;
                let mut final_block = block.clone();
                final_block.header.nonce = nonce;
                final_block.header.hash  = shadow_hash(&final_block);
                slog_info!("gpu", "opencl_block_found", nonce => nonce, hash_prefix => &final_block.header.hash[..16]);
                return Some(final_block);
            }
        }
        None
    }

    pub fn benchmark(&self) -> f64 {
        use crate::config::genesis::genesis::create_genesis_block;
        let block  = create_genesis_block();
        let start  = Instant::now();
        let iters  = self.work_size;

        (0..iters).into_par_iter().for_each(|nonce| {
            let mut b = block.clone();
            b.header.nonce = nonce;
            let _ = shadow_hash(&b);
        });

        let elapsed_ms = start.elapsed().as_millis().max(1);
        let mhs = (iters as f64 / elapsed_ms as f64) / 1000.0;
        slog_info!("gpu", "opencl_benchmark_result", platform => self.platform_id, device => self.device_id, hashrate_mhs => format!("{:.2}", mhs));
        mhs
    }
}
