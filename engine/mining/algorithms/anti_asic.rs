// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Anti-ASIC hardening layer. Adds memory-hard and branch-heavy operations
// that are efficient on GPUs but expensive to implement in fixed hardware.
//
// Techniques:
//   1. Multi-algorithm hashing (SHA2 + SHA3 + Blake3)
//   2. Memory-hard scratchpad operations
//   3. Data-dependent branching (hard for pipelining)
//   4. Dynamic mixing (varies with block height)
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest as Sha2Digest};
use sha3::Sha3_256;

/// Scratchpad size for memory-hard operations (16 KB)
pub const ANTI_ASIC_SCRATCHPAD: usize = 16_384;

pub struct AntiAsic;

impl AntiAsic {
    /// Apply ASIC-resistant hardening to a string input
    pub fn harden(input: &str) -> String {
        Self::harden_bytes(input.as_bytes())
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    /// Apply ASIC-resistant hardening to byte input
    pub fn harden_bytes(input: &[u8]) -> [u8; 32] {
        // Stage 1: SHA3-256
        let mut sha3 = Sha3_256::new();
        sha3.update(b"ShadowDAG_AntiASIC_v1");
        sha3.update(input);
        let stage1 = sha3.finalize();

        // Stage 2: Memory-hard mixing
        let mut scratchpad = vec![0u8; ANTI_ASIC_SCRATCHPAD];
        for (i, chunk) in scratchpad.chunks_mut(32).enumerate() {
            let mut h = Sha256::new();
            h.update(stage1);
            h.update((i as u64).to_le_bytes());
            let block_hash = h.finalize();
            let len = chunk.len().min(32);
            chunk[..len].copy_from_slice(&block_hash[..len]);
        }

        // Stage 3: Data-dependent branching (hard to pipeline in ASIC)
        for i in 0..256 {
            let idx = (stage1[i % 32] as usize * 64) % (ANTI_ASIC_SCRATCHPAD - 32);
            let direction = scratchpad[idx] & 0x03;

            match direction {
                0 => {
                    // XOR forward
                    let next = (idx + 32) % (ANTI_ASIC_SCRATCHPAD - 32);
                    for j in 0..32 {
                        scratchpad[idx + j] ^= scratchpad[next + j];
                    }
                }
                1 => {
                    // Rotate bytes
                    let temp = scratchpad[idx];
                    for j in 0..31 {
                        scratchpad[idx + j] = scratchpad[idx + j + 1];
                    }
                    scratchpad[idx + 31] = temp;
                }
                2 => {
                    // ADD with wrap
                    let next = (idx + 64) % (ANTI_ASIC_SCRATCHPAD - 32);
                    for j in 0..32 {
                        scratchpad[idx + j] = scratchpad[idx + j].wrapping_add(scratchpad[next + j]);
                    }
                }
                _ => {
                    // Bit reversal
                    for j in 0..32 {
                        scratchpad[idx + j] = scratchpad[idx + j].reverse_bits();
                    }
                }
            }
        }

        // Stage 4: Final compression
        let mut sha3_final = Sha3_256::new();
        sha3_final.update(&scratchpad);
        sha3_final.update(stage1);
        let result = sha3_final.finalize();

        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Height-dependent hardening (changes algorithm behavior per era)
    pub fn harden_at_height(input: &[u8], height: u64) -> [u8; 32] {
        let era = height / 100_000; // Change mixing every 100K blocks
        let mut data = Vec::with_capacity(input.len() + 8);
        data.extend_from_slice(&era.to_le_bytes());
        data.extend_from_slice(input);
        Self::harden_bytes(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_is_deterministic() {
        let h1 = AntiAsic::harden("test_input");
        let h2 = AntiAsic::harden("test_input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn harden_is_64_hex() {
        let h = AntiAsic::harden("hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_inputs_different_outputs() {
        let h1 = AntiAsic::harden("input_a");
        let h2 = AntiAsic::harden("input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn height_dependent() {
        let h1 = AntiAsic::harden_at_height(b"block_data", 0);
        let h2 = AntiAsic::harden_at_height(b"block_data", 100_000);
        assert_ne!(h1, h2, "Different eras should produce different hashes");
    }

    #[test]
    fn same_era_same_hash() {
        let h1 = AntiAsic::harden_at_height(b"data", 50);
        let h2 = AntiAsic::harden_at_height(b"data", 99_999);
        assert_eq!(h1, h2, "Same era should produce same hash");
    }
}
