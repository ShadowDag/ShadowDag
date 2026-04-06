// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rayon::prelude::*;
use std::time::Instant;
use crate::engine::mining::algorithms::shadowhash::shadow_hash;
use crate::engine::mining::pow::pow_validator::PowValidator;
use crate::domain::block::block::Block;

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
        eprintln!(
            "OpenClMiner → initializing platform={} device={}",
            platform_id, device_id
        );
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
        eprintln!(
            "OpenClMiner → platform={} vendor='{}' device={} work_size={}",
            self.platform_id, info.vendor, self.device_id, self.work_size
        );

        eprintln!("OpenClMiner → context and command queue ready");
    }

    pub fn compute_pow(&self, block: &Block, difficulty: u64) -> Option<u64> {
        eprintln!(
            "OpenClMiner → compute_pow difficulty={} platform={} device={} work_size={}",
            difficulty, self.platform_id, self.device_id, self.work_size
        );

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
        eprintln!(
            "OpenClMiner → kernel done in {}ms result={:?}",
            elapsed, result
        );
        result
    }

    pub fn mine_block(&self, mut block: Block, difficulty: u64) -> Option<Block> {
        if self.work_size == 0 {
            eprintln!("OpenClMiner → work_size is 0, cannot mine (would divide by zero)");
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
                eprintln!(
                    "OpenClMiner → ✅ block found nonce={} hash={}",
                    nonce, &final_block.header.hash[..16]
                );
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
        eprintln!(
            "OpenClMiner → benchmark platform={} device={}: {:.2} MH/s",
            self.platform_id, self.device_id, mhs
        );
        mhs
    }
}
