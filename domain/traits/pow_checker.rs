// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

/// Abstract PoW verification.
///
/// domain/ defines this trait; engine/mining implements it.
/// This breaks the domain → engine dependency.
pub trait PowChecker: Send + Sync {
    /// Verify that the given hash meets the target for the given difficulty.
    fn hash_meets_target(&self, hash: &str, difficulty: u64) -> bool;

    /// Compute the PoW hash for a block header.
    fn compute_pow_hash(&self, header_bytes: &[u8]) -> String;
}
