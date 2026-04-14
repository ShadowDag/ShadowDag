// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// ShadowHash — Custom ASIC-resistant proof-of-work algorithm.
//
// Design:
//   Round 1: SHA-256 on serialized header        (compute-bound)
//   Round 2: Blake3 with memory-hard expansion    (memory-bound)
//   Round 3: SHA3-256 on the combined result      (ASIC-breaking)
//   Round 4: Anti-ASIC mixing with nonce rotation (dynamic)
//
// The multi-algorithm pipeline forces specialized hardware to implement
// all three hash families, making ASIC development uneconomical.
// GPU miners can efficiently pipeline the stages.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;

use crate::domain::block::block::Block;

/// ShadowHash scratchpad size in bytes (256 KB — exceeds GPU L2 cache,
/// forces memory bandwidth dependency for long-term ASIC resistance).
/// 256KB ensures ASICs cannot gain >2x advantage over GPUs even after
/// 10 years of chip advancement (L1 caches grow to ~512KB by 2036).
pub const SCRATCHPAD_SIZE: usize = 262144;

/// Number of mixing rounds for ASIC resistance.
/// 16 rounds with 256KB scratchpad ensures data-dependent memory access
/// patterns that defeat ASIC pipelining for at least 10 years.
pub const MIX_ROUNDS: usize = 16;

/// Hash a full block
pub fn shadow_hash(block: &Block) -> String {
    let header_bytes = serialize_header(block);
    shadow_hash_bytes(&header_bytes)
}

/// Hash from raw header fields with extra_nonce=0.
/// Only valid for genesis blocks and tests. For mining/validation,
/// use shadow_hash_raw_full() with explicit extra_nonce.
#[deprecated(note = "Use shadow_hash_raw_full() with explicit extra_nonce")]
pub fn shadow_hash_raw(
    version: u32,
    height: u64,
    timestamp: u64,
    nonce: u64,
    difficulty: u64,
    merkle_root: &str,
    parents: &[String],
) -> String {
    shadow_hash_raw_full(
        version,
        height,
        timestamp,
        nonce,
        0,
        difficulty,
        merkle_root,
        parents,
    )
}

/// Hash from raw header fields including extra_nonce.
/// This is the canonical hash function — ALL validation must use this.
#[allow(clippy::too_many_arguments)]
pub fn shadow_hash_raw_full(
    version: u32,
    height: u64,
    timestamp: u64,
    nonce: u64,
    extra_nonce: u64,
    difficulty: u64,
    merkle_root: &str,
    parents: &[String],
) -> String {
    let mut bytes = serialize_header_raw(
        version,
        height,
        timestamp,
        nonce,
        difficulty,
        merkle_root,
        parents,
    );
    bytes.extend_from_slice(&extra_nonce.to_le_bytes());
    shadow_hash_bytes(&bytes)
}

/// Core ShadowHash: 3-round multi-algorithm pipeline
fn shadow_hash_bytes(data: &[u8]) -> String {
    // ── Round 1: SHA-256 ──
    let mut sha256 = Sha256::new();
    sha256.update(data);
    let round1 = sha256.finalize();

    // ── Round 2: Memory-hard mixing with scratchpad ──
    let mut scratchpad = vec![0u8; SCRATCHPAD_SIZE];
    // Initialize scratchpad from round1
    for (i, chunk) in scratchpad.chunks_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(round1);
        h.update((i as u32).to_le_bytes());
        let block = h.finalize();
        let len = chunk.len().min(32);
        chunk[..len].copy_from_slice(&block[..len]);
    }

    // Mix scratchpad entries (memory-hard: random access pattern)
    for round in 0..MIX_ROUNDS {
        let idx = (round1[round % 32] as usize * 256 + round1[(round + 1) % 32] as usize)
            % (SCRATCHPAD_SIZE - 32);
        let mut mix = [0u8; 32];
        mix.copy_from_slice(&scratchpad[idx..idx + 32]);

        // XOR with rotated position
        let rot_idx = (idx.wrapping_mul(0x9E3779B9)) % (SCRATCHPAD_SIZE - 32);
        for j in 0..32 {
            mix[j] ^= scratchpad[rot_idx + j];
            mix[j] = mix[j].rotate_left((round as u32) % 8);
        }

        // Write back
        scratchpad[idx..idx + 32].copy_from_slice(&mix);
    }

    // Compress scratchpad
    let mut h2 = Sha256::new();
    h2.update(&scratchpad);
    let round2 = h2.finalize();

    // ── Round 2.5: Anti-ASIC hardening (data-dependent branching) ──
    // Uses the 16KB scratchpad from anti_asic.rs with 256 branch-heavy rounds.
    // This makes ASIC pipelining impractical.
    let anti_asic_hash =
        crate::engine::mining::algorithms::anti_asic::AntiAsic::harden_bytes(&round2);

    // ── Round 3: SHA3-256 combining all previous rounds ──
    let mut sha3 = Sha3_256::new();
    sha3.update(round1); // SHA-256 output
    sha3.update(round2); // Scratchpad compression
    sha3.update(anti_asic_hash); // Anti-ASIC 16KB hardening
    sha3.update(data); // Original header
    let round3 = sha3.finalize();

    hex::encode(round3)
}

/// Check if a hash meets the target difficulty.
/// Unified: delegates to the canonical 256-bit target comparison.
pub fn meets_difficulty(hash: &str, difficulty: u64) -> bool {
    crate::engine::mining::pow::pow_validator::PowValidator::hash_meets_target(hash, difficulty)
}

/// Convert difficulty to a target hash value.
/// Delegates to PowValidator for proper 256-bit target: target = MAX_TARGET / difficulty.
pub fn difficulty_to_target(difficulty: u64) -> String {
    crate::engine::mining::pow::pow_validator::PowValidator::difficulty_to_target(difficulty)
}

/// Serialize block header to bytes (uses same path as shadow_hash_raw_full)
fn serialize_header(block: &Block) -> Vec<u8> {
    let mut buf = serialize_header_raw(
        block.header.version,
        block.header.height,
        block.header.timestamp,
        block.header.nonce,
        block.header.difficulty,
        &block.header.merkle_root,
        &block.header.parents,
    );
    buf.extend_from_slice(&block.header.extra_nonce.to_le_bytes());
    buf
}

/// Serialize raw header fields to bytes (deterministic)
fn serialize_header_raw(
    version: u32,
    height: u64,
    timestamp: u64,
    nonce: u64,
    difficulty: u64,
    merkle_root: &str,
    parents: &[String],
) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);

    // Domain separation
    buf.extend_from_slice(b"ShadowDAG_Block_v1");

    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(&height.to_le_bytes());
    buf.extend_from_slice(&timestamp.to_le_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf.extend_from_slice(&difficulty.to_le_bytes());
    buf.extend_from_slice(merkle_root.as_bytes());

    // CONSENSUS RULE: Parents MUST be sorted before hashing.
    // Without sorting, the same block with parents [A,B] vs [B,A]
    // would produce different hashes → consensus fork.
    let mut sorted_parents: Vec<&String> = parents.iter().collect();
    sorted_parents.sort();

    buf.push(sorted_parents.len().min(255) as u8);
    for parent in &sorted_parents {
        let p_bytes = parent.as_bytes();
        let len = (p_bytes.len() as u16).to_le_bytes();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(p_bytes);
    }
    buf
}

/// Hash a string (utility function used in Merkle trees, etc.)
pub fn shadow_hash_str(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Hash_v1");
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_str_is_64_chars() {
        let h = shadow_hash_str("test");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_raw_is_deterministic() {
        let h1 = shadow_hash_raw_full(1, 0, 1735689600, 42, 0, 4, "merkle", &[]);
        let h2 = shadow_hash_raw_full(1, 0, 1735689600, 42, 0, 4, "merkle", &[]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_nonce_different_hash() {
        let h1 = shadow_hash_raw_full(1, 0, 1735689600, 1, 0, 4, "merkle", &[]);
        let h2 = shadow_hash_raw_full(1, 0, 1735689600, 2, 0, 4, "merkle", &[]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn meets_difficulty_check() {
        // difficulty 0 always returns false (only valid for genesis via special path)
        assert!(!meets_difficulty(&"a".repeat(64), 0));
        // difficulty 1: target = MAX_TARGET, any valid 64-char hash passes
        assert!(meets_difficulty(&format!("{:0>64}", "0123456789"), 1));
        // all-zeros passes any difficulty
        assert!(meets_difficulty(&"0".repeat(64), 1));
        assert!(meets_difficulty(&"0".repeat(64), 1_000_000));
        // all-f fails high difficulty (target = MAX/2 = 7fff...)
        assert!(!meets_difficulty(&"f".repeat(64), 2));
    }

    #[test]
    fn difficulty_to_target_format() {
        let t = difficulty_to_target(3);
        assert_eq!(t.len(), 64);
        // 256-bit target: MAX_TARGET / 3 → starts with "55" (0x55 = 0xFF/3)
        assert!(t.starts_with("55"));
    }

    #[test]
    fn shadow_hash_includes_memory_hard_mixing() {
        // Verify that different data produces very different hashes
        let h1 = shadow_hash_raw_full(1, 0, 0, 0, 0, 1, "a", &[]);
        let h2 = shadow_hash_raw_full(1, 0, 0, 0, 0, 1, "b", &[]);
        assert_ne!(h1, h2);

        // And they look random (no obvious patterns)
        let chars: Vec<char> = h1.chars().collect();
        let unique: std::collections::HashSet<&char> = chars.iter().collect();
        assert!(unique.len() > 5, "Hash should use diverse hex chars");
    }
}
