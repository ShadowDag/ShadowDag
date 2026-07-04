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
        let gpu = match gpu_hashimoto(&dataset, &hh, &nonces) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("skipping GPU test (no device): {}", e);
                return;
            }
        };
        for (k, &nonce) in nonces.iter().enumerate() {
            let (cmix, cres) = umbrahash::hashimoto_full(&dataset, &hh, nonce);
            assert_eq!(&gpu[k * 64..k * 64 + 32], &cmix[..], "mix_hash mismatch nonce {}", nonce);
            assert_eq!(&gpu[k * 64 + 32..k * 64 + 64], &cres[..], "result mismatch nonce {}", nonce);
        }
    }
}
