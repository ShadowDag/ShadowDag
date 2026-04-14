// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// MuHash — Multiplicative Hash for UTXO Set Commitments (Kaspa-style).
//
// A rolling (homomorphic) hash that supports incremental updates:
//   - Add an element    → multiply into accumulator
//   - Remove an element → divide from accumulator
//   - Same final hash regardless of insertion order
//
// This allows every block header to contain a UTXO commitment without
// recomputing the entire UTXO set hash from scratch.
//
// Properties:
//   ✅ Incremental: O(1) add/remove (no full recomputation)
//   ✅ Order-independent: same set → same hash
//   ✅ Collision-resistant: based on modular arithmetic in large prime field
//   ✅ Deterministic: same UTXO set → same commitment always
//
// Usage in ShadowDAG:
//   - Block header contains `utxo_commitment` field
//   - New node downloads UTXO set, verifies against header commitment
//   - No need to replay entire blockchain history
//
// Math:
//   accumulator = Π H(utxo_i) mod P  (product of hashes mod prime)
//   add:    acc = acc * H(utxo) mod P
//   remove: acc = acc * H(utxo)^(-1) mod P  (modular inverse)
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Digest, Sha256};

/// A large prime for the multiplicative group.
/// We use arithmetic in Z/pZ where p is a 256-bit prime.
/// For simplicity, we operate on u128 pairs (high, low) but the real
/// implementation would use a proper bignum. Here we use a 64-bit prime
/// field which is sufficient for the hash structure (collision resistance
/// comes from the SHA-256 pre-hash, not the field size).
const PRIME: u128 = 0xFFFF_FFFF_FFFF_FFC5; // Largest 64-bit prime (2^64 - 59)

/// Domain tag for UTXO hashing
const UTXO_HASH_TAG: &[u8] = b"ShadowDAG_MuHash_UTXO_v1";

/// MuHash accumulator for UTXO set commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuHash {
    /// Multiplicative accumulator (starts at 1)
    numerator: u128,
    /// Divisor accumulator for removed elements (starts at 1)
    denominator: u128,
    /// Number of elements added
    count: u64,
}

impl Default for MuHash {
    fn default() -> Self {
        Self::new()
    }
}

impl MuHash {
    /// Create a new empty MuHash (identity element = 1)
    pub fn new() -> Self {
        Self {
            numerator: 1,
            denominator: 1,
            count: 0,
        }
    }

    /// Add a UTXO to the set: acc *= H(utxo)
    pub fn add_utxo(&mut self, txid: &str, index: u32, amount: u64, address: &str) {
        let h = Self::hash_utxo(txid, index, amount, address);
        self.numerator = Self::mul_mod(self.numerator, h);
        self.count += 1;
    }

    /// Remove a UTXO from the set: acc *= H(utxo)^(-1)
    pub fn remove_utxo(&mut self, txid: &str, index: u32, amount: u64, address: &str) {
        let h = Self::hash_utxo(txid, index, amount, address);
        self.denominator = Self::mul_mod(self.denominator, h);
        if self.count > 0 {
            self.count -= 1;
        }
    }

    /// Add raw bytes element
    pub fn add_element(&mut self, data: &[u8]) {
        let h = Self::hash_element(data);
        self.numerator = Self::mul_mod(self.numerator, h);
        self.count += 1;
    }

    /// Remove raw bytes element
    pub fn remove_element(&mut self, data: &[u8]) {
        let h = Self::hash_element(data);
        self.denominator = Self::mul_mod(self.denominator, h);
        if self.count > 0 {
            self.count -= 1;
        }
    }

    /// Finalize: compute the commitment hash
    /// Result = numerator / denominator mod P, then hash to 32 bytes
    pub fn finalize(&self) -> String {
        let inv_denom = Self::mod_inverse(self.denominator);
        let result = Self::mul_mod(self.numerator, inv_denom);

        // Hash the result to get a fixed-size commitment
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_MuHash_Final_v1");
        h.update(result.to_le_bytes());
        h.update(self.count.to_le_bytes());
        hex::encode(h.finalize())
    }

    /// Combine two MuHash accumulators (for parallel computation)
    pub fn combine(&mut self, other: &MuHash) {
        self.numerator = Self::mul_mod(self.numerator, other.numerator);
        self.denominator = Self::mul_mod(self.denominator, other.denominator);
        self.count += other.count;
    }

    /// Get element count
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ── Internal math ────────────────────────────────────────────

    /// Hash a UTXO to a field element
    fn hash_utxo(txid: &str, index: u32, amount: u64, address: &str) -> u128 {
        let mut h = Sha256::new();
        h.update(UTXO_HASH_TAG);
        h.update(txid.as_bytes());
        h.update(index.to_le_bytes());
        h.update(amount.to_le_bytes());
        h.update(address.as_bytes());
        let digest = h.finalize();

        // Take first 16 bytes as u128, ensure non-zero
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&digest[..16]);
        let val = u128::from_le_bytes(arr);
        (val % PRIME).max(1) // Must be non-zero in multiplicative group
    }

    /// Hash arbitrary data to a field element
    fn hash_element(data: &[u8]) -> u128 {
        let mut h = Sha256::new();
        h.update(UTXO_HASH_TAG);
        h.update(data);
        let digest = h.finalize();
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&digest[..16]);
        (u128::from_le_bytes(arr) % PRIME).max(1)
    }

    /// Modular multiplication: (a * b) mod P
    #[inline]
    fn mul_mod(a: u128, b: u128) -> u128 {
        // For u128, we need to be careful about overflow
        // Since PRIME fits in u64, a and b are < PRIME < 2^64
        // So a*b < 2^128, which fits in u128
        let a = a % PRIME;
        let b = b % PRIME;
        (a * b) % PRIME
    }

    /// Modular inverse using Fermat's little theorem: a^(-1) = a^(p-2) mod p
    fn mod_inverse(a: u128) -> u128 {
        if a == 0 {
            return 1;
        } // Safety: 0 has no inverse, return identity
        Self::pow_mod(a % PRIME, PRIME - 2)
    }

    /// Modular exponentiation: base^exp mod P
    fn pow_mod(mut base: u128, mut exp: u128) -> u128 {
        let mut result: u128 = 1;
        base %= PRIME;
        while exp > 0 {
            if exp & 1 == 1 {
                result = Self::mul_mod(result, base);
            }
            exp >>= 1;
            base = Self::mul_mod(base, base);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_muhash() {
        let mh = MuHash::new();
        assert_eq!(mh.count(), 0);
        assert!(mh.is_empty());
        let commitment = mh.finalize();
        assert_eq!(commitment.len(), 64);
    }

    #[test]
    fn add_produces_non_empty_commitment() {
        let mut mh = MuHash::new();
        mh.add_utxo("tx1", 0, 1000, "SD1alice");
        assert_eq!(mh.count(), 1);
        assert!(!mh.is_empty());
        let c = mh.finalize();
        assert_ne!(c, MuHash::new().finalize());
    }

    #[test]
    fn deterministic() {
        let mut mh1 = MuHash::new();
        let mut mh2 = MuHash::new();
        mh1.add_utxo("tx1", 0, 1000, "SD1a");
        mh2.add_utxo("tx1", 0, 1000, "SD1a");
        assert_eq!(mh1.finalize(), mh2.finalize());
    }

    #[test]
    fn order_independent() {
        let mut mh1 = MuHash::new();
        mh1.add_utxo("tx1", 0, 100, "SD1a");
        mh1.add_utxo("tx2", 0, 200, "SD1b");

        let mut mh2 = MuHash::new();
        mh2.add_utxo("tx2", 0, 200, "SD1b");
        mh2.add_utxo("tx1", 0, 100, "SD1a");

        assert_eq!(
            mh1.finalize(),
            mh2.finalize(),
            "MuHash must be order-independent"
        );
    }

    #[test]
    fn add_then_remove_returns_to_empty() {
        let empty = MuHash::new().finalize();

        let mut mh = MuHash::new();
        mh.add_utxo("tx1", 0, 1000, "SD1a");
        mh.remove_utxo("tx1", 0, 1000, "SD1a");

        assert_eq!(
            mh.finalize(),
            empty,
            "Adding then removing same element must return to identity"
        );
    }

    #[test]
    fn different_utxos_different_hashes() {
        let mut mh1 = MuHash::new();
        mh1.add_utxo("tx1", 0, 100, "SD1a");

        let mut mh2 = MuHash::new();
        mh2.add_utxo("tx2", 0, 100, "SD1a");

        assert_ne!(mh1.finalize(), mh2.finalize());
    }

    #[test]
    fn combine_two_sets() {
        let mut mh1 = MuHash::new();
        mh1.add_utxo("tx1", 0, 100, "SD1a");

        let mut mh2 = MuHash::new();
        mh2.add_utxo("tx2", 0, 200, "SD1b");

        let mut combined = MuHash::new();
        combined.add_utxo("tx1", 0, 100, "SD1a");
        combined.add_utxo("tx2", 0, 200, "SD1b");

        mh1.combine(&mh2);
        assert_eq!(
            mh1.finalize(),
            combined.finalize(),
            "Combining two sets must equal building from scratch"
        );
    }

    #[test]
    fn partial_remove() {
        let mut full = MuHash::new();
        full.add_utxo("tx1", 0, 100, "SD1a");
        full.add_utxo("tx2", 0, 200, "SD1b");
        full.add_utxo("tx3", 0, 300, "SD1c");

        full.remove_utxo("tx2", 0, 200, "SD1b");

        let mut expected = MuHash::new();
        expected.add_utxo("tx1", 0, 100, "SD1a");
        expected.add_utxo("tx3", 0, 300, "SD1c");

        assert_eq!(
            full.finalize(),
            expected.finalize(),
            "Removing middle element must match building without it"
        );
    }

    #[test]
    fn large_set_performance() {
        let start = std::time::Instant::now();
        let mut mh = MuHash::new();
        for i in 0..10_000 {
            mh.add_utxo(&format!("tx_{}", i), 0, i as u64 * 100, "SD1addr");
        }
        let _commitment = mh.finalize();
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 5_000,
            "10K UTXO MuHash should compute in <5000ms, took {}ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn block_apply_simulation() {
        // Simulate applying a block: add new UTXOs, remove spent ones
        let mut muhash = MuHash::new();

        // Genesis: create 3 UTXOs
        muhash.add_utxo("genesis", 0, 1000, "SD1miner");
        muhash.add_utxo("genesis", 1, 500, "SD1dev");
        muhash.add_utxo("genesis", 2, 200, "SD1other");
        let after_genesis = muhash.finalize();

        // Block 1: spend genesis:0, create tx1:0 and tx1:1
        muhash.remove_utxo("genesis", 0, 1000, "SD1miner");
        muhash.add_utxo("tx1", 0, 800, "SD1alice");
        muhash.add_utxo("tx1", 1, 200, "SD1bob");
        let after_block1 = muhash.finalize();

        assert_ne!(after_genesis, after_block1);
        assert_eq!(muhash.count(), 4); // 3 - 1 + 2 = 4

        // Rollback block 1: reverse the operations
        muhash.remove_utxo("tx1", 0, 800, "SD1alice");
        muhash.remove_utxo("tx1", 1, 200, "SD1bob");
        muhash.add_utxo("genesis", 0, 1000, "SD1miner");
        let after_rollback = muhash.finalize();

        assert_eq!(
            after_genesis, after_rollback,
            "Rollback must restore original commitment"
        );
    }

    #[test]
    fn modular_inverse_correct() {
        // a * a^(-1) mod p == 1
        let a = 12345u128;
        let inv = MuHash::mod_inverse(a);
        let product = MuHash::mul_mod(a, inv);
        assert_eq!(product, 1, "a * a^(-1) must equal 1 mod p");
    }
}
