// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// REAL OpenCL GPU miner for ShadowHash. Unlike the removed stub miners, this
// executes the actual ShadowHash pipeline (SHA-256 + 256KB memory-hard mixing +
// anti-ASIC + SHA3) on the GPU via a kernel that is byte-for-byte identical to
// the CPU consensus hash — validated per stage against `shadow_hash_of_bytes`.
//
// Feature-gated (`gpu-opencl`) so the default build stays dependency-free.
// ═══════════════════════════════════════════════════════════════════════════

use ocl::{Buffer, Context, Device, Kernel, Platform, Program, Queue};

/// Per-work-item memory-hard scratchpad sizes — MUST equal the kernel's SP256/SP16
/// and the CPU `SCRATCHPAD_SIZE` / `ANTI_ASIC_SCRATCHPAD`.
pub const SP256: usize = 262_144;
pub const SP16: usize = 16_384;

/// The proven kernel, embedded at build time.
const KERNEL_SRC: &str = include_str!("shadowhash.cl");

/// A ready-to-mine OpenCL context bound to one GPU device, with the large
/// per-work-item scratchpads allocated once and reused across batches.
pub struct OpenClMiner {
    device_name: String,
    batch: usize,
    queue: Queue,
    program: Program,
    sp256: Buffer<u8>,
    sp16: Buffer<u8>,
}

impl OpenClMiner {
    /// Initialize on the best available GPU. `batch` = work-items per kernel
    /// launch (each needs 256KB+16KB of VRAM scratchpad; ~8192 is a good default
    /// on a 6GB card — 20k+ exceeds efficient VRAM and slows down).
    pub fn new(batch: usize) -> Result<Self, String> {
        let (platform, device) = pick_device()?;
        let device_name = device.name().map_err(|e| e.to_string())?;
        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()
            .map_err(|e| e.to_string())?;
        let program = Program::builder()
            .src(KERNEL_SRC)
            .devices(device)
            .build(&context)
            .map_err(|e| format!("kernel build failed: {}", e))?;
        let queue = Queue::new(&context, device, None).map_err(|e| e.to_string())?;
        let sp256 = Buffer::<u8>::builder()
            .queue(queue.clone())
            .len(batch * SP256)
            .build()
            .map_err(|e| format!("VRAM alloc (256KB x {}) failed: {}", batch, e))?;
        let sp16 = Buffer::<u8>::builder()
            .queue(queue.clone())
            .len(batch * SP16)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { device_name, batch, queue, program, sp256, sp16 })
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }
    pub fn batch(&self) -> usize {
        self.batch
    }

    /// Try `batch` nonces starting at `base_nonce`. Each work-item copies
    /// `header_template`, overwrites the 8 bytes at `nonce_offset` with its
    /// candidate nonce, computes ShadowHash, and — if the hash ≤ `target`
    /// (big-endian) — records the winning nonce. Returns the first winner found.
    pub fn mine_batch(
        &self,
        header_template: &[u8],
        nonce_offset: usize,
        target: &[u8; 32],
        base_nonce: u64,
    ) -> Result<Option<u64>, String> {
        if header_template.len() > 512 {
            return Err("header template exceeds the kernel's 512-byte cap".into());
        }
        if nonce_offset + 8 > header_template.len() {
            return Err("nonce_offset out of range for template".into());
        }
        let tmpl = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .len(header_template.len())
            .copy_host_slice(header_template)
            .build()
            .map_err(|e| e.to_string())?;
        let tgt = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .len(32)
            .copy_host_slice(&target[..])
            .build()
            .map_err(|e| e.to_string())?;
        let res = Buffer::<u32>::builder()
            .queue(self.queue.clone())
            .len(3)
            .copy_host_slice(&[0u32; 3])
            .build()
            .map_err(|e| e.to_string())?;

        let kernel = Kernel::builder()
            .program(&self.program)
            .name("shadowhash_mine")
            .queue(self.queue.clone())
            .global_work_size(self.batch)
            .arg(&tmpl)
            .arg(header_template.len() as u32)
            .arg(nonce_offset as u32)
            .arg(base_nonce)
            .arg(&tgt)
            .arg(&self.sp256)
            .arg(&self.sp16)
            .arg(&res)
            .build()
            .map_err(|e| e.to_string())?;
        unsafe {
            kernel.enq().map_err(|e| e.to_string())?;
        }
        self.queue.finish().map_err(|e| e.to_string())?;

        let mut r = [0u32; 3];
        res.read(&mut r[..]).enq().map_err(|e| e.to_string())?;
        if r[0] == 0 {
            Ok(None)
        } else {
            Ok(Some(r[1] as u64 | ((r[2] as u64) << 32)))
        }
    }
}

/// Pick a GPU device, preferring discrete vendors; fall back to the first device.
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
    fallback.ok_or_else(|| "no OpenCL device found (install a GPU driver)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::mining::algorithms::shadowhash::shadow_hash_of_bytes;

    #[test]
    fn gpu_mine_finds_a_nonce_the_cpu_accepts() {
        // Easy target: hash's first byte must be 0x00 (~1/256). A 8192-nonce
        // batch should find one; the CPU hash of that nonce must also meet it.
        let miner = match OpenClMiner::new(8192) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("skipping GPU test (no device): {}", e);
                return;
            }
        };
        let mut tmpl = vec![0u8; 120];
        for (i, b) in tmpl.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let nonce_off = 38usize;
        let mut target = [0xffu8; 32];
        target[0] = 0x00;

        let mut found = None;
        for round in 0..8u64 {
            if let Some(n) = miner
                .mine_batch(&tmpl, nonce_off, &target, round * 8192)
                .expect("mine_batch")
            {
                found = Some(n);
                break;
            }
        }
        let nonce = found.expect("a 1/256 target should yield a nonce within 64k tries");
        tmpl[nonce_off..nonce_off + 8].copy_from_slice(&nonce.to_le_bytes());
        let hash = shadow_hash_of_bytes(&tmpl);
        assert_eq!(&hash[..2], "00", "GPU-found nonce must satisfy the target on the CPU (got {})", &hash[..8]);
    }
}
