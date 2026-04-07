// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// PoW Validator — Validates proof-of-work using numeric target comparison.
//
// Uses proper 256-bit target comparison (hash <= target) instead of just
// counting leading zeros. This gives finer-grained difficulty adjustment.
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block::Block;
use crate::domain::block::block_header::BlockHeader;
use crate::engine::mining::algorithms::shadowhash::shadow_hash;

/// Maximum target: 2^256 - 1, represented as 32 bytes (all 0xFF).
/// In hex this is 64 'f' characters.
const MAX_TARGET_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Maximum allowed difficulty (bounded by 256-bit space).
/// At max difficulty the target is 1, meaning only the zero hash qualifies.
pub const MAX_DIFFICULTY: u64 = u64::MAX / 2;

/// Minimum allowed difficulty
pub const MIN_DIFFICULTY: u64 = 1;

pub struct PowValidator;

impl PowValidator {
    /// Full block PoW validation
    pub fn validate(block: &Block) -> PowResult {
        // 1. Recompute the hash using ShadowHash
        let computed_hash = shadow_hash(block);

        // 2. Verify hash matches header
        if computed_hash != block.header.hash {
            return PowResult::fail(format!(
                "hash mismatch: computed={}... header={}...",
                &computed_hash[..16.min(computed_hash.len())],
                &block.header.hash[..16.min(block.header.hash.len())]
            ));
        }

        // 3. Validate that ShadowHash was used (hash must be exactly 64 hex chars
        //    as produced by the ShadowHash pipeline)
        if !Self::is_valid_shadowhash_format(&computed_hash) {
            return PowResult::fail(
                "hash is not a valid ShadowHash output (must be 64 lowercase hex chars)".to_string(),
            );
        }

        // 4. Difficulty == 0 is only valid for the genesis block (height 0)
        if block.header.difficulty == 0 && block.header.height > 0 {
            return PowResult::fail(
                "difficulty 0 is not valid for non-genesis blocks".to_string(),
            );
        }

        // 5. Validate difficulty range (allow 0 only for genesis, checked above)
        if block.header.difficulty > 0
            && block.header.difficulty < MIN_DIFFICULTY
        {
            return PowResult::fail(format!(
                "difficulty {} below minimum {}",
                block.header.difficulty, MIN_DIFFICULTY
            ));
        }

        // 6. Verify hash meets target (proper 256-bit numeric comparison)
        if block.header.difficulty > 0
            && !Self::hash_meets_target(&computed_hash, block.header.difficulty)
        {
            return PowResult::fail(format!(
                "hash {} does not meet difficulty {} target",
                &computed_hash[..16], block.header.difficulty
            ));
        }

        PowResult::ok(computed_hash)
    }

    /// Validate a header independently (recompute hash from fields including extra_nonce)
    pub fn validate_header(header: &BlockHeader) -> bool {
        use crate::engine::mining::algorithms::shadowhash::shadow_hash_raw_full;
        let recomputed = shadow_hash_raw_full(
            header.version,
            header.height,
            header.timestamp,
            header.nonce,
            header.extra_nonce,
            header.difficulty,
            &header.merkle_root,
            &header.parents,
        );

        if recomputed != header.hash {
            return false;
        }

        // Verify ShadowHash format
        if !Self::is_valid_shadowhash_format(&recomputed) {
            return false;
        }

        // difficulty == 0 only valid at height 0
        if header.difficulty == 0 && header.height > 0 {
            return false;
        }

        // If difficulty > 0, check target
        if header.difficulty > 0 {
            Self::hash_meets_target(&recomputed, header.difficulty)
        } else {
            true // genesis block with difficulty 0
        }
    }

    /// Check if a hash meets the target for a given difficulty.
    /// Uses proper 256-bit numeric comparison: hash_value <= target_value
    /// where target = MAX_TARGET / difficulty.
    pub fn hash_meets_target(hash: &str, difficulty: u64) -> bool {
        // difficulty == 0 is only valid for genesis; non-genesis callers must
        // not reach here with 0. Return false as a safety net.
        if difficulty == 0 {
            return false;
        }
        if hash.len() != 64 {
            return false;
        }

        // Convert hash hex string to 32-byte array
        let hash_bytes = match Self::hex_to_bytes32(hash) {
            Some(b) => b,
            None => return false,
        };

        // Compute target = MAX_TARGET / difficulty as 256-bit big-endian
        let target_bytes = Self::difficulty_to_target_bytes(difficulty);

        // Compare hash <= target (big-endian byte comparison)
        hash_bytes <= target_bytes
    }

    /// Convert difficulty to a 256-bit target: target = MAX_TARGET / difficulty.
    /// Returns 32-byte big-endian representation.
    fn difficulty_to_target_bytes(difficulty: u64) -> [u8; 32] {
        if difficulty == 0 {
            return [0xFF; 32]; // MAX_TARGET
        }
        if difficulty == 1 {
            return [0xFF; 32]; // MAX_TARGET / 1 = MAX_TARGET
        }

        // Perform 256-bit division: MAX_TARGET / difficulty
        // MAX_TARGET = 2^256 - 1, but for practical purposes we use 2^256 / difficulty
        // which is the standard Bitcoin-style target calculation.
        //
        // We compute this as: (2^256 - 1) / difficulty using long division
        // on a 32-byte big-endian number.
        let mut target = [0xFF_u8; 32];
        Self::div_256bit_by_u64(&mut target, difficulty);
        target
    }

    /// Divide a 256-bit big-endian number in place by a u64 divisor.
    fn div_256bit_by_u64(num: &mut [u8; 32], divisor: u64) {
        if divisor == 0 {
            // Difficulty 0 = impossible target; return all-ones (easiest)
            *num = [0xFF; 32];
            return;
        }
        let mut remainder: u128 = 0;
        for byte in num.iter_mut() {
            remainder = (remainder << 8) | (*byte as u128);
            *byte = (remainder / divisor as u128) as u8;
            remainder %= divisor as u128;
        }
    }

    /// Convert difficulty to a target hex string (for display / compatibility).
    /// target = MAX_TARGET / difficulty
    pub fn difficulty_to_target(difficulty: u64) -> String {
        if difficulty == 0 {
            return MAX_TARGET_HEX.to_string();
        }
        let bytes = Self::difficulty_to_target_bytes(difficulty);
        hex::encode(bytes)
    }

    /// Parse a 64-char hex string into a 32-byte array.
    fn hex_to_bytes32(hex_str: &str) -> Option<[u8; 32]> {
        if hex_str.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let pair = hex_str.get(i * 2..i * 2 + 2)?;
            *byte = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(bytes)
    }

    /// Validate that a hash has the format produced by ShadowHash:
    /// exactly 64 lowercase hex characters.
    fn is_valid_shadowhash_format(hash: &str) -> bool {
        hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    }

    /// Estimate hashrate from difficulty and block time.
    /// With proper target math: expected attempts = MAX_TARGET / target = difficulty.
    pub fn estimated_hashrate(difficulty: u64, block_time_secs: u64) -> f64 {
        if block_time_secs == 0 { return 0.0; }
        // The expected number of hashes to find a valid block is proportional
        // to difficulty (since target = MAX_TARGET / difficulty).
        difficulty as f64 / block_time_secs as f64
    }
}

#[derive(Debug)]
pub struct PowResult {
    pub valid:         bool,
    pub reason:        Option<String>,
    pub computed_hash: Option<String>,
}

impl PowResult {
    pub fn ok(hash: String) -> Self {
        Self { valid: true, reason: None, computed_hash: Some(hash) }
    }
    pub fn fail(reason: String) -> Self {
        Self { valid: false, reason: Some(reason), computed_hash: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_for_difficulty_1_is_max() {
        let t = PowValidator::difficulty_to_target(1);
        assert_eq!(t.len(), 64);
        assert_eq!(t, MAX_TARGET_HEX);
    }

    #[test]
    fn target_decreases_with_higher_difficulty() {
        let t1 = PowValidator::difficulty_to_target(10);
        let t2 = PowValidator::difficulty_to_target(100);
        // Higher difficulty => lower (smaller) target hex
        assert!(t2 < t1);
    }

    #[test]
    fn hash_below_target_passes() {
        // Difficulty 1 => target is MAX, so any valid hash should pass
        let hash = format!("{:0>64}", "abcdef1234567890");
        assert!(PowValidator::hash_meets_target(&hash, 1));
    }

    #[test]
    fn all_zeros_hash_passes_any_difficulty() {
        let hash = "0".repeat(64);
        assert!(PowValidator::hash_meets_target(&hash, 1));
        assert!(PowValidator::hash_meets_target(&hash, 1_000_000));
    }

    #[test]
    fn all_f_hash_fails_high_difficulty() {
        let hash = "f".repeat(64);
        // At difficulty 2, target is MAX_TARGET/2 which is ~7fff...
        // An all-f hash should fail
        assert!(!PowValidator::hash_meets_target(&hash, 2));
    }

    #[test]
    fn difficulty_zero_returns_false() {
        // difficulty == 0 should now return false (no bypass)
        assert!(!PowValidator::hash_meets_target(&"0".repeat(64), 0));
    }

    #[test]
    fn invalid_hash_length_fails() {
        assert!(!PowValidator::hash_meets_target("ffff", 1));
        assert!(!PowValidator::hash_meets_target(&"f".repeat(63), 1));
    }

    #[test]
    fn shadowhash_format_validation() {
        assert!(PowValidator::is_valid_shadowhash_format(&"a".repeat(64)));
        assert!(!PowValidator::is_valid_shadowhash_format(&"A".repeat(64)));
        assert!(!PowValidator::is_valid_shadowhash_format(&"a".repeat(63)));
        assert!(!PowValidator::is_valid_shadowhash_format(&format!("{}g", "a".repeat(63))));
    }

    #[test]
    fn hashrate_estimation() {
        let hr = PowValidator::estimated_hashrate(1000, 10);
        assert!((hr - 100.0).abs() < 0.001);
    }

    #[test]
    fn div_256bit_correctness() {
        // MAX_TARGET / 2 should give 7f...ff
        let target = PowValidator::difficulty_to_target_bytes(2);
        assert_eq!(target[0], 0x7F);
        for &b in &target[1..] {
            assert_eq!(b, 0xFF);
        }
    }
}
