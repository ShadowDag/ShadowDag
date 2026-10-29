// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// UmbraHash on the GPU (OpenCL). Runs dataset-item generation, hashimoto, and
// the nonce-search mining kernel — all byte-for-byte identical to the CPU
// engine/mining/algorithms/umbrahash.rs (the acceptance oracle). Feature-gated
// (`gpu-opencl`); reuses the OpenCL toolchain set up for the ShadowHash miner.
// ═══════════════════════════════════════════════════════════════════════════

use ocl::{Buffer, Context, Device, Kernel, Platform, Program, Queue};

const KERNEL_SRC: &str = include_str!("umbrahash.cl");

fn pick_device() -> Result<(Platform, Device), String> {
    let mut fallback: Option<(Platform, Device)> = None;
    for platform in Platform::list() {
        for d in Device::list_all(platform).unwrap_or_default() {
            let name = d.name().unwrap_or_default().to_uppercase();
            if fallback.is_none() {
                fallback = Some((platform, d));
            }
            if ["NVIDIA", "GEFORCE", "RTX", "AMD", "RADEON", "INTEL"]
                .iter()
                .any(|v| name.contains(v))
                && !name.contains("CPU")
            {
                return Ok((platform, d));
            }
        }
    }
    fallback.ok_or_else(|| "no OpenCL device found".to_string())
}

fn build(device: Device, platform: Platform) -> Result<(Program, Queue), String> {
    let context = Context::builder()
        .platform(platform)
        .devices(device)
        .build()
        .map_err(|e| e.to_string())?;
    let program = Program::builder()
        .src(KERNEL_SRC)
        .devices(device)
        .build(&context)
        .map_err(|e| format!("UmbraHash kernel build failed: {}", e))?;
    let queue = Queue::new(&context, device, None).map_err(|e| e.to_string())?;
    Ok((program, queue))
}

/// Compute `count` dataset items starting at `base` on the GPU. Returns
/// `count * 64` bytes.
pub fn gpu_calc_items(cache: &[u8], base: u32, count: usize) -> Result<Vec<u8>, String> {
    let (platform, device) = pick_device()?;
    let (program, queue) = build(device, platform)?;
    let n = (cache.len() / 64) as u32;

    let cache_buf = Buffer::<u8>::builder()
        .queue(queue.clone())
        .len(cache.len())
        .copy_host_slice(cache)
        .build()
        .map_err(|e| e.to_string())?;
    let out_buf = Buffer::<u8>::builder()
        .queue(queue.clone())
        .len(count * 64)
        .build()
        .map_err(|e| e.to_string())?;

    let kernel = Kernel::builder()
        .program(&program)
        .name("umbra_calc_items")
        .queue(queue.clone())
        .global_work_size(count)
        .arg(&cache_buf)
        .arg(n)
        .arg(base)
        .arg(&out_buf)
        .build()
        .map_err(|e| e.to_string())?;
    unsafe {
        kernel.enq().map_err(|e| e.to_string())?;
    }
    queue.finish().map_err(|e| e.to_string())?;

    let mut out = vec![0u8; count * 64];
    out_buf.read(&mut out).enq().map_err(|e| e.to_string())?;
    Ok(out)
}

/// Run hashimoto for each nonce over the resident dataset. Returns
/// `nonces.len() * 64` bytes (each = mix_hash[32] ‖ result[32]).
pub fn gpu_hashimoto(
    dataset: &[u8],
    header_hash: &[u8; 32],
    nonces: &[u64],
    prog_seed: u64,
) -> Result<Vec<u8>, String> {
    let (platform, device) = pick_device()?;
    let (program, queue) = build(device, platform)?;
    let n = (dataset.len() / 64) as u32;

    let ds_buf = Buffer::<u8>::builder()
        .queue(queue.clone())
        .len(dataset.len())
        .copy_host_slice(dataset)
        .build()
        .map_err(|e| e.to_string())?;
    let hh_buf = Buffer::<u8>::builder()
        .queue(queue.clone())
        .len(32)
        .copy_host_slice(&header_hash[..])
        .build()
        .map_err(|e| e.to_string())?;
    let nonce_buf = Buffer::<u64>::builder()
        .queue(queue.clone())
        .len(nonces.len())
        .copy_host_slice(nonces)
        .build()
        .map_err(|e| e.to_string())?;
    let out_buf = Buffer::<u8>::builder()
        .queue(queue.clone())
        .len(nonces.len() * 64)
        .build()
        .map_err(|e| e.to_string())?;

    let kernel = Kernel::builder()
        .program(&program)
        .name("umbra_hashimoto")
        .queue(queue.clone())
        .global_work_size(nonces.len())
        .arg(&ds_buf)
        .arg(n)
        .arg(&hh_buf)
        .arg(&nonce_buf)
        .arg(prog_seed)
        .arg(&out_buf)
        .build()
        .map_err(|e| e.to_string())?;
    unsafe {
        kernel.enq().map_err(|e| e.to_string())?;
    }
    queue.finish().map_err(|e| e.to_string())?;

    let mut out = vec![0u8; nonces.len() * 64];
    out_buf.read(&mut out).enq().map_err(|e| e.to_string())?;
    Ok(out)
}

/// A GPU UmbraHash miner: generates the (large) dataset once per epoch into VRAM,
/// then searches nonces against it with the `umbra_mine` kernel. Reuses the
/// OpenCL toolchain. `dataset_bytes`/`cache_bytes` are parameters so the miner
/// uses the consensus sizes (umbrahash::DATASET_BYTES / CACHE_BYTES) while tests
/// can use small ones.
pub struct UmbraGpuMiner {
    device_name: String,
    batch: usize,
    cache_bytes: usize,
    n: u32,
    queue: Queue,
    program: Program,
    dataset: Buffer<u8>,
    loaded_epoch: Option<u64>,
}

impl UmbraGpuMiner {
    pub fn new(batch: usize, dataset_bytes: usize, cache_bytes: usize) -> Result<Self, String> {
        let (platform, device) = pick_device()?;
        let device_name = device.name().map_err(|e| e.to_string())?;
        let (program, queue) = build(device, platform)?;
        let dataset = Buffer::<u8>::builder()
            .queue(queue.clone())
            .len(dataset_bytes)
            .build()
            .map_err(|e| format!("VRAM dataset alloc ({} bytes) failed: {}", dataset_bytes, e))?;
        Ok(Self {
            device_name,
            batch,
            cache_bytes,
            n: (dataset_bytes / 64) as u32,
            queue,
            program,
            dataset,
            loaded_epoch: None,
        })
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }
    pub fn batch(&self) -> usize {
        self.batch
    }

    /// Generate the epoch dataset into VRAM (once per epoch). `cache` must be the
    /// `cache_bytes`-sized cache for `epoch`.
    pub fn ensure_dataset(&mut self, cache: &[u8], epoch: u64) -> Result<(), String> {
        if self.loaded_epoch == Some(epoch) {
            return Ok(());
        }
        if cache.len() != self.cache_bytes {
            return Err("cache size mismatch".into());
        }
        let cache_buf = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .len(cache.len())
            .copy_host_slice(cache)
            .build()
            .map_err(|e| e.to_string())?;
        let cache_n = (self.cache_bytes / 64) as u32;
        let items = self.n as usize;
        let gen_batch = 262_144usize.min(items); // work-items per launch
        let mut base = 0usize;
        while base < items {
            let this = gen_batch.min(items - base);
            let kernel = Kernel::builder()
                .program(&self.program)
                .name("umbra_calc_items")
                .queue(self.queue.clone())
                .global_work_size(this)
                .arg(&cache_buf)
                .arg(cache_n)
                .arg(base as u32)
                .arg(&self.dataset)
                .build()
                .map_err(|e| e.to_string())?;
            unsafe {
                kernel.enq().map_err(|e| e.to_string())?;
            }
            base += this;
        }
        self.queue.finish().map_err(|e| e.to_string())?;
        self.loaded_epoch = Some(epoch);
        Ok(())
    }

    /// Search `batch` nonces from `base_nonce` against the resident dataset.
    /// Returns the first nonce whose result <= target (caller recomputes
    /// mix/result on the CPU for the header + a consensus cross-check).
    pub fn mine(
        &self,
        header_hash: &[u8; 32],
        target: &[u8; 32],
        prog_seed: u64,
        base_nonce: u64,
    ) -> Result<Option<u64>, String> {
        let hh_buf = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .len(32)
            .copy_host_slice(&header_hash[..])
            .build()
            .map_err(|e| e.to_string())?;
        let tgt_buf = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .len(32)
            .copy_host_slice(&target[..])
            .build()
            .map_err(|e| e.to_string())?;
        let res_buf = Buffer::<u32>::builder()
            .queue(self.queue.clone())
            .len(3)
            .copy_host_slice(&[0u32; 3])
            .build()
            .map_err(|e| e.to_string())?;
        let win_buf = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .len(32)
            .build()
            .map_err(|e| e.to_string())?;

        let kernel = Kernel::builder()
            .program(&self.program)
            .name("umbra_mine")
            .queue(self.queue.clone())
            .global_work_size(self.batch)
            .arg(&self.dataset)
            .arg(self.n)
            .arg(&hh_buf)
            .arg(base_nonce)
            .arg(prog_seed)
            .arg(&tgt_buf)
            .arg(&res_buf)
            .arg(&win_buf)
            .build()
            .map_err(|e| e.to_string())?;
        unsafe {
            kernel.enq().map_err(|e| e.to_string())?;
        }
        self.queue.finish().map_err(|e| e.to_string())?;

        let mut r = [0u32; 3];
        res_buf.read(&mut r[..]).enq().map_err(|e| e.to_string())?;
        if r[0] == 0 {
            Ok(None)
        } else {
            Ok(Some(r[1] as u64 | ((r[2] as u64) << 32)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::mining::algorithms::umbrahash;

    const CACHE_SIZE: usize = 64 * 128;
    const FULL_SIZE: usize = 64 * 512;

    #[test]
    fn gpu_dataset_items_match_cpu() {
        let cache = umbrahash::mkcache(CACHE_SIZE, &umbrahash::epoch_seed(0));
        let count = 64usize;
        let gpu = match gpu_calc_items(&cache, 0, count) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("skipping GPU test (no device): {}", e);
                return;
            }
        };
        for i in 0..count {
            let cpu = umbrahash::calc_dataset_item(&cache, i as u32);
            assert_eq!(
                &gpu[i * 64..i * 64 + 64],
                &cpu[..],
                "GPU dataset item {} != CPU",
                i
            );
        }
    }

    #[test]
    fn gpu_miner_finds_nonce_the_cpu_accepts() {
        const DS: usize = 64 * 512; // 512 dataset items
        const CS: usize = 64 * 128; // 128 cache items
        let mut miner = match UmbraGpuMiner::new(4096, DS, CS) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("skipping GPU miner test (no device): {}", e);
                return;
            }
        };
        let cache = umbrahash::mkcache(CS, &umbrahash::epoch_seed(0));
        miner.ensure_dataset(&cache, 0).expect("dataset gen");
        let header: [u8; 32] = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(b"gpu-mine");
            h.finalize().into()
        };
        let mut target = [0xffu8; 32];
        target[0] = 0x00; // ~1/256

        let ps = 3u64;
        let mut found = None;
        for round in 0..16u64 {
            if let Some(n) = miner.mine(&header, &target, ps, round * 4096).expect("mine") {
                found = Some(n);
                break;
            }
        }
        let nonce = found.expect("a 1/256 target should yield a nonce within 64k");
        // CPU cross-check: the GPU-found nonce must pass node light-verify.
        let (mix, _result) = umbrahash::hashimoto_light(&cache, DS, &header, nonce, ps);
        assert!(
            umbrahash::verify_light(&cache, DS, &header, nonce, ps, &mix, &target),
            "GPU-found nonce must pass CPU light-verify"
        );
    }

    #[test]
    fn gpu_hashimoto_matches_cpu() {
        let cache = umbrahash::mkcache(CACHE_SIZE, &umbrahash::epoch_seed(0));
        let dataset = umbrahash::generate_dataset(&cache, FULL_SIZE);
        let hh: [u8; 32] = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(b"umbra-header");
            h.finalize().into()
        };
        let nonces: Vec<u64> = vec![1, 2, 42, 12_345, 0xdead_beef, u64::MAX];
        let ps = 5u64;
        let gpu = match gpu_hashimoto(&dataset, &hh, &nonces, ps) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("skipping GPU test (no device): {}", e);
                return;
            }
        };
        for (k, &nonce) in nonces.iter().enumerate() {
            let (cmix, cres) = umbrahash::hashimoto_full(&dataset, &hh, nonce, ps);
            assert_eq!(&gpu[k * 64..k * 64 + 32], &cmix[..], "mix_hash mismatch nonce {}", nonce);
            assert_eq!(&gpu[k * 64 + 32..k * 64 + 64], &cres[..], "result mismatch nonce {}", nonce);
        }
    }

    #[test]
    #[ignore = "GPU hashrate benchmark; run with --release --features gpu-opencl -- --ignored --nocapture"]
    fn umbra_gpu_hashrate_benchmark() {
        use std::time::{Duration, Instant};

        let epoch = 0u64;
        let seed = umbrahash::epoch_seed(epoch);
        let t_cache = Instant::now();
        let cache = umbrahash::mkcache(umbrahash::CACHE_BYTES, &seed);
        let cache_secs = t_cache.elapsed().as_secs_f64();
        let prog_seed = umbrahash::prog_seed_from_height(0);

        let header: [u8; 32] = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(b"umbra-gpu-hashrate-benchmark");
            h.finalize().into()
        };
        let impossible_target = [0u8; 32];

        println!(
            "\n=== UmbraHash GPU hashrate benchmark (consensus sizes: dataset={} MiB, cache={} MiB) ===",
            umbrahash::DATASET_BYTES >> 20,
            umbrahash::CACHE_BYTES >> 20
        );
        println!("cache built on CPU in {:.2}s", cache_secs);

        let window = Duration::from_secs(12);
        for &batch in &[8192usize, 32768, 131072] {
            let mut miner = match UmbraGpuMiner::new(batch, umbrahash::DATASET_BYTES, umbrahash::CACHE_BYTES) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("skipping GPU benchmark (no device): {}", e);
                    return;
                }
            };
            let t_ds = Instant::now();
            miner.ensure_dataset(&cache, epoch).expect("dataset gen");
            let ds_secs = t_ds.elapsed().as_secs_f64();

            for w in 0..4u64 {
                let hit = miner
                    .mine(&header, &impossible_target, prog_seed, w * batch as u64)
                    .expect("warmup mine");
                assert!(hit.is_none(), "impossible target must never win");
            }

            let mut base: u64 = 1_000 * batch as u64;
            let mut calls: u64 = 0;
            let start = Instant::now();
            while start.elapsed() < window {
                let hit = miner.mine(&header, &impossible_target, prog_seed, base).expect("mine");
                assert!(hit.is_none(), "impossible target must never win");
                calls += 1;
                base = base.wrapping_add(batch as u64);
            }
            let elapsed = start.elapsed().as_secs_f64();
            let hashes = calls * batch as u64;
            let hps = hashes as f64 / elapsed;
            println!(
                "device={} batch={:>7} dataset_gen={:.2}s | {:>6} batches, {:>10} hashes in {:.2}s => {:>8.0} H/s ({:.2} kH/s)",
                miner.device_name(),
                batch,
                ds_secs,
                calls,
                hashes,
                elapsed,
                hps,
                hps / 1000.0
            );
        }
        println!("=== end benchmark ===\n");
    }
}
