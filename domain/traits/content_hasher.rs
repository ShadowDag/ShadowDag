// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

/// Abstract content hashing.
///
/// domain/ defines this trait; engine/crypto implements it.
/// This breaks the domain → engine dependency for hash computation.
pub trait ContentHasher: Send + Sync {
    /// Hash arbitrary bytes, returning a hex-encoded digest.
    fn hash_bytes(&self, data: &[u8]) -> String;

    /// Hash a string, returning a hex-encoded digest.
    fn hash_str(&self, s: &str) -> String {
        self.hash_bytes(s.as_bytes())
    }
}
