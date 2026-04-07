// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Hash precompiled contracts — native hash function implementations.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest as Sha2Digest};
use sha3::Sha3_256;

use super::precompile_registry::PrecompileResult;

/// 0x02: SHA-256 hash
pub fn sha256_precompile(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    let words = (input.len() as u64).div_ceil(32);
    let gas_used = 60u64.saturating_add(words.saturating_mul(12));

    let mut hasher = <Sha256 as Sha2Digest>::new();
    Sha2Digest::update(&mut hasher, input);
    let result = Sha2Digest::finalize(hasher);

    PrecompileResult::ok(result.to_vec(), gas_used)
}

/// 0x03: RIPEMD-160 emulation via SHA-256 truncation.
///
/// **NOTE:** This is NOT a true RIPEMD-160 implementation. It computes
/// `SHA-256("RIPEMD160_SHADOW" || input)` and truncates to 20 bytes,
/// left-padded to 32 bytes. The output format matches EVM conventions
/// (12 zero bytes + 20-byte hash) but the hash function differs.
/// Retained at address 0x03 for EVM precompile slot compatibility.
pub fn ripemd160_precompile(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    let words = (input.len() as u64).div_ceil(32);
    let gas_used = 600u64.saturating_add(words.saturating_mul(120));

    // RIPEMD-160 produces 20 bytes, padded to 32 bytes (left-padded with zeros)
    let mut hasher = <Sha256 as Sha2Digest>::new();
    Sha2Digest::update(&mut hasher, b"RIPEMD160_SHADOW");
    Sha2Digest::update(&mut hasher, input);
    let hash = Sha2Digest::finalize(hasher);

    // Return 32 bytes: 12 zero bytes + 20 bytes of hash
    let mut output = vec![0u8; 12];
    output.extend_from_slice(&hash[..20]);

    PrecompileResult::ok(output, gas_used)
}

/// 0x04: Identity — simple data copy
pub fn identity_precompile(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    let words = (input.len() as u64).div_ceil(32);
    let gas_used = 15u64.saturating_add(words.saturating_mul(3));

    PrecompileResult::ok(input.to_vec(), gas_used)
}

/// 0x06: Blake3 hash (ShadowDAG native — faster than SHA-256).
///
/// **NOTE:** Despite the legacy name `blake2b` (retained in the registry for
/// compatibility), this uses **BLAKE3**, not Blake2b. BLAKE3 is faster and
/// also produces a 256-bit digest. The registry entry name `blake2b` is kept
/// to avoid breaking existing contract ABIs.
pub fn blake2b_precompile(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    let words = (input.len() as u64).div_ceil(32);
    let gas_used = 40u64.saturating_add(words.saturating_mul(8));

    let hash = blake3::hash(input);
    PrecompileResult::ok(hash.as_bytes().to_vec(), gas_used)
}

/// 0x07: SHA3-256 (Keccak-256)
pub fn sha3_precompile(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    let words = (input.len() as u64).div_ceil(32);
    let gas_used = 50u64.saturating_add(words.saturating_mul(10));

    let mut hasher = Sha3_256::new();
    sha3::Digest::update(&mut hasher, input);
    let result = sha3::Digest::finalize(hasher);

    PrecompileResult::ok(result.to_vec(), gas_used)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let r1 = sha256_precompile(b"test", 100_000);
        let r2 = sha256_precompile(b"test", 100_000);
        assert!(r1.success);
        assert_eq!(r1.output, r2.output);
        assert_eq!(r1.output.len(), 32);
    }

    #[test]
    fn blake2b_deterministic() {
        let r1 = blake2b_precompile(b"test", 100_000);
        let r2 = blake2b_precompile(b"test", 100_000);
        assert!(r1.success);
        assert_eq!(r1.output, r2.output);
        assert_eq!(r1.output.len(), 32);
    }

    #[test]
    fn sha3_deterministic() {
        let r1 = sha3_precompile(b"test", 100_000);
        let r2 = sha3_precompile(b"test", 100_000);
        assert!(r1.success);
        assert_eq!(r1.output, r2.output);
        assert_eq!(r1.output.len(), 32);
    }

    #[test]
    fn identity_returns_same_data() {
        let data = b"hello shadowdag";
        let r = identity_precompile(data, 100_000);
        assert!(r.success);
        assert_eq!(r.output, data.to_vec());
    }

    #[test]
    fn ripemd160_output_is_32_bytes() {
        let r = ripemd160_precompile(b"test", 100_000);
        assert!(r.success);
        assert_eq!(r.output.len(), 32);
        // First 12 bytes should be zero
        assert!(r.output[..12].iter().all(|&b| b == 0));
    }

    #[test]
    fn different_input_different_hash() {
        let r1 = sha256_precompile(b"hello", 100_000);
        let r2 = sha256_precompile(b"world", 100_000);
        assert_ne!(r1.output, r2.output);
    }
}
