// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Hash precompiled contracts — native hash function implementations.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Digest as Sha2Digest, Sha256};
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

/// 0x03: RIPEMD-160, EVM-compatible. Real RIPEMD-160 over the input; the
/// 20-byte digest is left-padded to 32 bytes per EVM convention.
pub fn ripemd160_precompile(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    use ripemd::{Digest as RipemdDigest, Ripemd160};
    let words = (input.len() as u64).div_ceil(32);
    let gas_used = 600u64.saturating_add(words.saturating_mul(120));

    let mut hasher = Ripemd160::new();
    RipemdDigest::update(&mut hasher, input);
    let hash = hasher.finalize();

    // EVM convention: the 20-byte digest left-padded to 32 bytes.
    let mut output = vec![0u8; 12];
    output.extend_from_slice(&hash);

    PrecompileResult::ok(output, gas_used)
}

/// 0x04: Identity — simple data copy
pub fn identity_precompile(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    let words = (input.len() as u64).div_ceil(32);
    let gas_used = 15u64.saturating_add(words.saturating_mul(3));

    PrecompileResult::ok(input.to_vec(), gas_used)
}

/// 0x06: BLAKE3 hash (ShadowDAG native -- faster than SHA-256).
///
/// This precompile computes a BLAKE3 256-bit digest. It is registered at
/// address 0x06 (the former Blake2b slot). The implementation has always used
/// BLAKE3, never Blake2b -- the old function name was misleading.
///
/// **WARNING:** The registry address 0x06 historically displayed as "blake2b".
/// Existing contract ABIs referencing address 0x06 will continue to work but
/// the underlying algorithm is BLAKE3.
pub fn blake3_precompile(input: &[u8], _gas_limit: u64) -> PrecompileResult {
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
    fn blake3_deterministic() {
        let r1 = blake3_precompile(b"test", 100_000);
        let r2 = blake3_precompile(b"test", 100_000);
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
    fn ripemd160_known_answer_vectors() {
        // Real RIPEMD-160 KATs, left-padded to 32 bytes per EVM convention.
        let empty = ripemd160_precompile(b"", 100_000);
        assert_eq!(
            hex::encode(&empty.output[12..32]),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
        let abc = ripemd160_precompile(b"abc", 100_000);
        assert_eq!(
            hex::encode(&abc.output[12..32]),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn different_input_different_hash() {
        let r1 = sha256_precompile(b"hello", 100_000);
        let r2 = sha256_precompile(b"world", 100_000);
        assert_ne!(r1.output, r2.output);
    }
}
