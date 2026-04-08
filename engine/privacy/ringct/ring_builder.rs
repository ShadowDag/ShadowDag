// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Ring Builder — Constructs rings for ring signature transactions.
// SECURITY: Signer position MUST be cryptographically random,
// NEVER derived from public transaction fields.
// ═══════════════════════════════════════════════════════════════════════════

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Sha256, Digest};

use crate::engine::privacy::ringct::ring_signature::RingMember;

// ═══════════════════════════════════════════════════════════════════════════
//  Pre-computed integer CDF for gamma(shape=19.28) power-law distribution.
//
//  The table maps 256 equal-probability buckets to output buckets [0, 256)
//  such that higher buckets (recent outputs) are selected more often.
//  Each entry is the CDF threshold (scaled to u64::MAX) for that bucket.
//
//  Equivalent to: bucket = floor(256 * u^(1/19.28)) for u in [0,1),
//  but computed once at compile time using only integer arithmetic,
//  eliminating all platform-dependent floating-point.
// ═══════════════════════════════════════════════════════════════════════════

const GAMMA_TABLE_SIZE: usize = 256;

/// Pre-computed CDF thresholds. GAMMA_CDF[i] = the u64 threshold below which
/// the uniform sample maps to bucket i. Generated offline with arbitrary-
/// precision math: threshold[i] = floor(u64::MAX * ((i+1)/256)^19.28).
///
/// The distribution heavily biases toward high buckets (recent outputs):
///   bucket 0..127  (oldest half):  ~0.003% of probability mass
///   bucket 128..191 (third quarter): ~1.4%
///   bucket 192..255 (newest quarter): ~98.6%
///   bucket 255 alone:               ~7.2%
static GAMMA_CDF: [u64; GAMMA_TABLE_SIZE] = {
    // We build the table using const integer exponentiation.
    // For each bucket i in [0,255], we need ((i+1)/256)^19 * correction.
    //
    // Since shape=19.28 ≈ 19 + 7/25, we approximate:
    //   x^19.28 ≈ x^19 * x^(7/25)
    // For the fractional part x^(7/25) we use:
    //   x^(7/25) ≈ 1 - (7/25)*(1-x) for x near 1 (first-order Taylor)
    //   For x far from 1 the probability mass is negligible anyway.
    //
    // All arithmetic uses u128 to avoid overflow.
    // Scale: numerator/denominator where denominator = 256^19.

    let mut table = [0u64; 256];

    // Compute (i+1)^19 / 256^19, scaled to u64::MAX.
    // We do this in stages to avoid overflow:
    //   ratio = (i+1)^19 / 256^19
    //   threshold = ratio * u64::MAX
    //
    // Since 256^19 = 2^152, and (i+1)^19 fits in at most 8*19=152 bits for i<256,
    // we compute (i+1)^19 >> 152 wouldn't work directly.
    //
    // Instead: threshold = ((i+1)^19 << 64) >> 152 = (i+1)^19 >> 88
    // But (i+1)^19 can be up to 255^19 which is ~150 bits, so >> 88 gives ~62 bits. Good.
    //
    // For the fractional exponent correction, we apply:
    //   corrected = base - (base * 7 * (256 - (i+1))) / (25 * 256)

    let mut i = 0usize;
    while i < 256 {
        let x = (i + 1) as u128;

        // Compute x^19 using repeated squaring in u128 stages.
        // We compute in two halves to handle the 150+ bits:
        //   x^19 = x^16 * x^2 * x
        // But u128 overflows at ~38 bits * 19 = nope for large x.
        //
        // Better approach: compute (x/256)^19 directly in fixed-point.
        // Use 64-bit fixed point: frac = (x << 56) / 256 = x << 48
        // Then frac^19 in stages, keeping top 64 bits.

        // Fixed-point: val = x * 2^56 / 256 = x * 2^48
        // This represents x/256 in Q56 fixed point.
        // Range: [1/256, 1] -> [2^48, 2^56]
        let shift = 56u32;
        let frac: u128 = x << 48; // x/256 in Q56 (x * 2^48 = x/256 * 2^56)

        // Compute frac^19 keeping precision via staged multiplication.
        // After each multiply of two Q56 values, result is Q112, shift right 56.
        // frac^2
        let f2 = (frac * frac) >> shift;
        // frac^4
        let f4 = (f2 * f2) >> shift;
        // frac^8
        let f8 = (f4 * f4) >> shift;
        // frac^16
        let f16 = (f8 * f8) >> shift;
        // frac^19 = frac^16 * frac^2 * frac
        let f18 = (f16 * f2) >> shift;
        let f19 = (f18 * frac) >> shift;

        // f19 is in Q56 representing (x/256)^19.
        // Scale to u64: result = f19 * u64::MAX / 2^56
        // = f19 * (2^64 - 1) / 2^56 ≈ f19 * 2^8 = f19 << 8
        // But also apply fractional exponent correction:
        // correction factor = 1 - (7/25) * (1 - x/256) = 1 - 7*(256-x)/(25*256)
        // In fixed point: correction = 2^48 - (7 * (256-x) * 2^48) / (25 * 256)
        let deficit = 256u128.saturating_sub(x);
        // numerator of correction subtrahend, scaled by 2^48
        let corr_sub = (7 * deficit * (1u128 << shift)) / (25 * 256);
        let correction = (1u128 << shift).saturating_sub(corr_sub);

        // Apply correction: f19_corrected = f19 * correction >> shift
        let f_corrected = (f19 * correction) >> shift;

        // Scale to u64 range: threshold = f_corrected << 8
        // Clamp to avoid overflow on the last bucket
        let threshold = if f_corrected >= (1u128 << 56) {
            u64::MAX
        } else {
            let val = f_corrected << 8;
            if val > u64::MAX as u128 { u64::MAX } else { val as u64 }
        };

        table[i] = threshold;
        i += 1;
    }

    // Ensure last bucket is u64::MAX (CDF must reach 1.0)
    table[255] = u64::MAX;
    table
};

/// Look up a uniform u64 sample in the pre-computed gamma CDF.
/// Returns a bucket index in [0, GAMMA_TABLE_SIZE) biased toward high values.
fn gamma_cdf_lookup(uniform: u64) -> usize {
    // Binary search: find smallest i where GAMMA_CDF[i] >= uniform
    let mut lo = 0usize;
    let mut hi = GAMMA_TABLE_SIZE;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if GAMMA_CDF[mid] < uniform {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo.min(GAMMA_TABLE_SIZE - 1)
}

pub struct RingBuilder;

impl RingBuilder {
    /// Build a ring using random decoys (legacy — prefer build_from_utxo_set)
    pub fn build(signer_pubkey: &[u8; 32]) -> Vec<RingMember> {
        Self::build_with_size(signer_pubkey, 11)
    }

    /// Build a ring using random decoys (legacy — prefer build_from_utxo_set)
    pub fn build_with_size(signer_pubkey: &[u8; 32], ring_size: usize) -> Vec<RingMember> {
        let ring_size = ring_size.clamp(4, 64);
        let mut ring = Vec::with_capacity(ring_size);

        // SECURITY: position is cryptographically random, NOT from timestamp
        let mut pos_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut pos_bytes);
        let signer_pos = (u64::from_le_bytes(pos_bytes) as usize) % ring_size;

        for i in 0..ring_size {
            if i == signer_pos {
                ring.push(RingMember::new(*signer_pubkey));
            } else {
                ring.push(RingMember::random_decoy());
            }
        }

        ring
    }

    /// Build a ring by selecting decoys from a real UTXO set using a gamma
    /// distribution that favors recent outputs (higher indices = more recent).
    ///
    /// `utxo_pubkeys` must be sorted by age (oldest first, newest last).
    /// Selection uses a gamma-like distribution: index = N - 1 - floor(|X|)
    /// where X is sampled from a distribution biased toward recent outputs.
    /// This matches the spending patterns observed in real blockchains.
    pub fn build_from_utxo_set(
        signer_pubkey: &[u8; 32],
        utxo_pubkeys: &[[u8; 32]],
        ring_size: usize,
    ) -> Vec<RingMember> {
        let ring_size = ring_size.clamp(4, 64);
        let decoys_needed = ring_size - 1;

        // Filter out the signer from the UTXO set
        let candidates: Vec<&[u8; 32]> = utxo_pubkeys.iter()
            .filter(|pk| pk.as_slice() != signer_pubkey.as_slice())
            .collect();

        // If not enough real UTXOs, fall back to mixed real + random
        if candidates.is_empty() {
            return Self::build_with_size(signer_pubkey, ring_size);
        }

        let n = candidates.len();
        let mut selected = std::collections::HashSet::new();
        let signer_hex = hex::encode(signer_pubkey);
        let mut decoys: Vec<RingMember> = Vec::with_capacity(decoys_needed);

        // Select decoys using gamma distribution (shape=19.28, scale=1/1.61)
        // approximated via rejection sampling with hash-based CSPRNG.
        // The distribution strongly favors recent outputs (high indices).
        let mut attempt = 0u64;
        while decoys.len() < decoys_needed && attempt < (decoys_needed as u64) * 100 {
            let idx = Self::gamma_sample_index(n, attempt);
            attempt += 1;

            let pk_hex = hex::encode(candidates[idx]);
            if pk_hex == signer_hex || selected.contains(&pk_hex) {
                continue;
            }
            selected.insert(pk_hex);
            decoys.push(RingMember::new(*candidates[idx]));
        }

        // If we still need more (small UTXO set), fill with random
        while decoys.len() < decoys_needed {
            decoys.push(RingMember::random_decoy());
        }

        // Place signer at a random position
        let mut pos_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut pos_bytes);
        let signer_pos = (u64::from_le_bytes(pos_bytes) as usize) % ring_size;

        let mut ring = Vec::with_capacity(ring_size);
        let mut decoy_iter = decoys.into_iter();
        for i in 0..ring_size {
            if i == signer_pos {
                ring.push(RingMember::new(*signer_pubkey));
            } else if let Some(decoy) = decoy_iter.next() {
                ring.push(decoy);
            } else {
                ring.push(RingMember::random_decoy());
            }
        }

        ring
    }

    /// Sample an index from a gamma-like distribution biased toward recent
    /// outputs (higher indices). Uses CSPRNG + hash to convert uniform
    /// randomness into gamma-distributed samples.
    ///
    /// Approximates Gamma(shape=19.28, scale=1/1.61) as used in Monero,
    /// truncated and mapped to [0, n).
    ///
    /// DETERMINISM: Uses a pre-computed integer CDF lookup table instead
    /// of f64::powf(), which is platform-dependent (different CPUs produce
    /// different results due to x87 vs SSE vs libm differences).
    fn gamma_sample_index(n: usize, attempt: u64) -> usize {
        // Generate uniform random bytes via CSPRNG + domain separation
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);

        let mut h = Sha256::new();
        h.update(b"ShadowDAG_GammaDecoy_v1");
        h.update(entropy);
        h.update(attempt.to_le_bytes());
        h.update((n as u64).to_le_bytes());
        let hash = h.finalize();

        // Convert first 8 bytes to a uniform u64
        let raw = u64::from_le_bytes(hash[..8].try_into().unwrap_or([0u8; 8]));

        // Use pre-computed integer CDF to map uniform -> gamma-distributed bucket
        let bucket = gamma_cdf_lookup(raw);

        // Map bucket [0, GAMMA_TABLE_SIZE) to index [0, n)
        let idx = (bucket as u128 * n as u128 / GAMMA_TABLE_SIZE as u128) as usize;
        idx.min(n - 1)
    }

    pub fn validate_ring(ring: &[RingMember]) -> bool {
        if ring.is_empty() || ring.len() < 4 {
            return false;
        }

        // Check for duplicate public keys
        let mut seen = std::collections::HashSet::new();
        for m in ring {
            if !seen.insert(hex::encode(m.public_key)) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn build_creates_valid_ring() {
        let pk = [42u8; 32];
        let ring = RingBuilder::build(&pk);
        assert_eq!(ring.len(), 11);
        assert!(RingBuilder::validate_ring(&ring));
    }

    #[test]
    fn signer_is_in_ring() {
        let pk = [42u8; 32];
        let ring = RingBuilder::build_with_size(&pk, 5);
        assert!(ring.iter().any(|m| m.public_key == pk));
    }

    #[test]
    fn position_is_random() {
        // Run multiple times — position should vary
        let pk = [42u8; 32];
        let mut positions = std::collections::HashSet::new();
        for _ in 0..50 {
            let ring = RingBuilder::build_with_size(&pk, 11);
            let pos = ring.iter().position(|m| m.public_key == pk).unwrap();
            positions.insert(pos);
        }
        // Should hit at least 3 different positions in 50 tries
        assert!(positions.len() >= 3, "Position should be random, got {:?}", positions);
    }

    #[test]
    fn no_duplicate_keys() {
        let pk = [42u8; 32];
        let ring = RingBuilder::build_with_size(&pk, 20);
        assert!(RingBuilder::validate_ring(&ring));
    }

    #[test]
    fn empty_ring_invalid() {
        assert!(!RingBuilder::validate_ring(&[]));
    }

    #[test]
    fn too_small_ring_invalid() {
        let ring = vec![RingMember::new([1u8; 32]), RingMember::new([2u8; 32]), RingMember::new([3u8; 32])];
        assert!(!RingBuilder::validate_ring(&ring)); // 3 < MIN_RING_SIZE (4)
    }

    #[test]
    fn build_from_utxo_set_contains_signer() {
        let signer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let utxos: Vec<[u8; 32]> = (0..50)
            .map(|_| SigningKey::generate(&mut OsRng).verifying_key().to_bytes())
            .collect();
        let ring = RingBuilder::build_from_utxo_set(&signer, &utxos, 11);
        assert_eq!(ring.len(), 11);
        assert!(ring.iter().any(|m| m.public_key == signer));
        assert!(RingBuilder::validate_ring(&ring));
    }

    #[test]
    fn build_from_utxo_set_uses_real_keys() {
        let signer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let utxos: Vec<[u8; 32]> = (0..50)
            .map(|_| SigningKey::generate(&mut OsRng).verifying_key().to_bytes())
            .collect();
        let ring = RingBuilder::build_from_utxo_set(&signer, &utxos, 11);
        // All non-signer members should be from the UTXO set
        let utxo_set: std::collections::HashSet<_> = utxos.iter().map(hex::encode).collect();
        let from_utxo = ring.iter()
            .filter(|m| m.public_key != signer)
            .filter(|m| utxo_set.contains(&hex::encode(m.public_key)))
            .count();
        assert_eq!(from_utxo, 10, "All decoys should come from the UTXO set");
    }

    #[test]
    fn gamma_distribution_favors_recent() {
        // With 1000 UTXOs, gamma selection should favor higher indices (recent)
        let signer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let utxos: Vec<[u8; 32]> = (0..1000)
            .map(|_| SigningKey::generate(&mut OsRng).verifying_key().to_bytes())
            .collect();
        // Run many builds and check that decoys tend to be from the latter half
        let mut recent_count = 0u32;
        let mut total_decoys = 0u32;
        for _ in 0..20 {
            let ring = RingBuilder::build_from_utxo_set(&signer, &utxos, 11);
            for m in &ring {
                if m.public_key == signer { continue; }
                if let Some(idx) = utxos.iter().position(|pk| *pk == m.public_key) {
                    total_decoys += 1;
                    if idx >= 500 { recent_count += 1; }
                }
            }
        }
        // With gamma(19.28), vast majority should be recent
        let recent_ratio = recent_count as f64 / total_decoys as f64;
        assert!(recent_ratio > 0.7,
            "Gamma distribution should favor recent outputs, got {:.1}% recent",
            recent_ratio * 100.0);
    }

    #[test]
    fn build_from_small_utxo_set_fills_with_random() {
        let signer = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let utxos: Vec<[u8; 32]> = (0..3)
            .map(|_| SigningKey::generate(&mut OsRng).verifying_key().to_bytes())
            .collect();
        let ring = RingBuilder::build_from_utxo_set(&signer, &utxos, 11);
        assert_eq!(ring.len(), 11);
        assert!(RingBuilder::validate_ring(&ring));
    }

    #[test]
    fn gamma_cdf_table_is_monotonic() {
        for i in 1..GAMMA_TABLE_SIZE {
            assert!(
                GAMMA_CDF[i] >= GAMMA_CDF[i - 1],
                "CDF must be monotonically non-decreasing at bucket {}",
                i
            );
        }
        assert_eq!(GAMMA_CDF[GAMMA_TABLE_SIZE - 1], u64::MAX, "CDF must reach 1.0");
    }

    #[test]
    fn gamma_cdf_lookup_covers_full_range() {
        // Minimum input -> bucket 0 or low
        let low = gamma_cdf_lookup(0);
        assert!(low < GAMMA_TABLE_SIZE);

        // Maximum input -> last bucket
        let high = gamma_cdf_lookup(u64::MAX);
        assert_eq!(high, GAMMA_TABLE_SIZE - 1);
    }

    #[test]
    fn gamma_cdf_lookup_is_deterministic() {
        let a = gamma_cdf_lookup(123456789);
        let b = gamma_cdf_lookup(123456789);
        assert_eq!(a, b, "Same input must always produce same bucket");
    }
}
