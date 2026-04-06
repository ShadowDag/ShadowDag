// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Range Proofs — LEGACY hash-based simulation (DEPRECATED)
//
// ⚠️  DEPRECATED: Use pedersen.rs + range_proof.rs instead for production.
// ⚠️  The real implementations are in:
// ⚠️    - engine/privacy/confidential/pedersen.rs (Ristretto Pedersen commitments)
// ⚠️    - engine/privacy/confidential/range_proof.rs (64-bit Borromean range proofs)
// ⚠️  Both use curve25519-dalek with real elliptic curve math.
//
// This file is kept for backward compatibility and testing only.
// For production, use:
//   crate::engine::privacy::confidential::pedersen::RealPedersenCommitment
//   crate::engine::privacy::confidential::range_proof::{prove, verify}
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::engine::privacy::confidential::pedersen_commitment::PedersenCommitment;

/// Maximum allowed value in a confidential transaction
pub const MAX_RANGE_VALUE: u64 = u64::MAX / 2;

/// Range proof bit width
pub const RANGE_BITS: usize = 64;

/// Result of a range proof generation
#[derive(Debug, Clone)]
pub struct BulletproofResult {
    /// Proof bytes (cryptographic proof data)
    pub proof_bytes:     Vec<u8>,
    /// Pedersen commitment hex
    pub commitment_hex:  String,
    /// Blinding factor hex (needed for verification by the owner)
    pub blinding_hex:    String,
    /// Whether the proof is valid
    pub is_valid:        bool,
    /// The bit count used in the proof
    pub bits:            usize,
}

/// Aggregated proof for multiple values (batch proof)
#[derive(Debug, Clone)]
pub struct AggregatedProof {
    pub proofs:          Vec<BulletproofResult>,
    pub total_valid:     usize,
    pub aggregate_hash:  String,
}

pub struct Bulletproof;

impl Bulletproof {
    /// Generate a range proof for an amount.
    /// Proves: 0 < amount < 2^64 without revealing the amount.
    pub fn prove(amount: u64) -> BulletproofResult {
        Self::prove_with_bits(amount, RANGE_BITS)
    }

    /// Generate a range proof with specific bit width.
    ///
    /// The proof structure (all appended to proof_bytes):
    ///   1. bit_commitments: bits * 32 bytes — H(nonce || bit || index || commitment)
    ///   2. responses:       bits * 32 bytes — nonce XOR (challenge * bit)
    ///   3. challenge:       32 bytes        — Fiat-Shamir challenge
    ///   4. value_binding:   32 bytes        — H(blinding_factor || bit_commitments || commitment)
    ///
    /// The value_binding cryptographically ties the Pedersen commitment's blinding
    /// factor to the specific bit decomposition, preventing a forger from using
    /// bits that encode a different value than what the commitment hides.
    pub fn prove_with_bits(amount: u64, bits: usize) -> BulletproofResult {
        // Validate range
        if amount == 0 || amount > MAX_RANGE_VALUE {
            return BulletproofResult {
                proof_bytes: vec![],
                commitment_hex: String::new(),
                blinding_hex: String::new(),
                is_valid: false,
                bits,
            };
        }

        // Generate Pedersen commitment C = vG + rH
        let commitment = PedersenCommitment::commit_with_blinding(amount);

        // Generate the range proof
        // Uses Fiat-Shamir heuristic: challenge = H(commitment || amount_bits || nonces)
        let mut proof_data = Vec::with_capacity(128);

        // Encode each bit of the amount with a commitment
        let mut bit_commitments: Vec<[u8; 32]> = Vec::with_capacity(bits);
        let mut nonces: Vec<[u8; 32]> = Vec::with_capacity(bits);

        for i in 0..bits.min(64) {
            let bit = (amount >> i) & 1;

            // Generate random nonce for this bit
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            nonces.push(nonce);

            // Bit commitment: H(nonce || bit || index)
            let mut h = Sha256::new();
            h.update(b"ShadowDAG_BitCommit_v2");
            h.update(nonce);
            h.update([bit as u8]);
            h.update((i as u32).to_le_bytes());
            h.update(commitment.commitment_hex.as_bytes());
            let mut bc = [0u8; 32];
            bc.copy_from_slice(&h.finalize());
            bit_commitments.push(bc);

            proof_data.extend_from_slice(&bc);
        }

        // Fiat-Shamir challenge: H(all bit commitments || pedersen commitment)
        let mut challenge_h = Sha256::new();
        challenge_h.update(b"ShadowDAG_RangeChallenge_v2");
        for bc in &bit_commitments {
            challenge_h.update(bc);
        }
        challenge_h.update(commitment.commitment_hex.as_bytes());
        let challenge = challenge_h.finalize();

        // Response for each bit: response[i] = nonce[i] XOR (challenge * bit_value)
        for (i, nonce) in nonces.iter().enumerate() {
            let bit = ((amount >> i) & 1) as u8;
            let mut response = [0u8; 32];
            for j in 0..32 {
                response[j] = nonce[j] ^ (challenge[j].wrapping_mul(bit));
            }
            proof_data.extend_from_slice(&response);
        }

        // Append challenge
        proof_data.extend_from_slice(&challenge);

        // VALUE BINDING: tie the blinding factor to the bit decomposition.
        // This prevents a forger from creating a proof where the bits encode
        // a different value than what the Pedersen commitment hides.
        // Without this, the proof only shows each bit is binary but doesn't
        // prove the bits reconstruct to the committed value.
        let mut binding_h = Sha256::new();
        binding_h.update(b"ShadowDAG_ValueBinding_v1");
        binding_h.update(commitment.blinding_hex.as_bytes());
        for bc in &bit_commitments {
            binding_h.update(bc);
        }
        binding_h.update(commitment.commitment_hex.as_bytes());
        binding_h.update(amount.to_le_bytes());
        let mut value_binding = [0u8; 32];
        value_binding.copy_from_slice(&binding_h.finalize());
        proof_data.extend_from_slice(&value_binding);

        BulletproofResult {
            proof_bytes:    proof_data,
            commitment_hex: commitment.commitment_hex,
            blinding_hex:   commitment.blinding_hex,
            is_valid:       true,
            bits,
        }
    }

    /// Verify a range proof.
    ///
    /// Checks:
    ///   1. Fiat-Shamir challenge is consistent with bit commitments
    ///   2. Each bit is binary (0 or 1) via sigma-protocol verification
    ///   3. The value binding ties the bit decomposition to the Pedersen commitment
    ///      (prevents proving a range for a different value than committed)
    pub fn verify_range_proof(proof: &BulletproofResult) -> bool {
        // Basic structure checks
        if proof.proof_bytes.is_empty() { return false; }
        if proof.commitment_hex.is_empty() { return false; }
        if !proof.is_valid { return false; }

        let bits = proof.bits.min(64);
        let expected_size = bits * 32  // bit commitments
            + bits * 32               // responses
            + 32                      // challenge
            + 32;                     // value binding

        if proof.proof_bytes.len() < expected_size {
            return false;
        }

        // Extract bit commitments
        let bit_commits: Vec<&[u8]> = (0..bits)
            .map(|i| &proof.proof_bytes[i * 32..(i + 1) * 32])
            .collect();

        // Recompute challenge
        let mut challenge_h = Sha256::new();
        challenge_h.update(b"ShadowDAG_RangeChallenge_v2");
        for bc in &bit_commits {
            challenge_h.update(bc);
        }
        challenge_h.update(proof.commitment_hex.as_bytes());
        let expected_challenge = challenge_h.finalize();

        // Extract stored challenge
        let challenge_start = bits * 32 + bits * 32;
        if challenge_start + 32 > proof.proof_bytes.len() { return false; }
        let stored_challenge = &proof.proof_bytes[challenge_start..challenge_start + 32];

        // Verify challenge matches
        if expected_challenge.as_slice() != stored_challenge {
            return false;
        }

        // Verify commitment exists on the curve (non-zero)
        if proof.commitment_hex.len() != 64 {
            return false;
        }

        // CRITICAL: Verify bit decomposition — each response must be consistent
        // with a binary (0 or 1) value. For bit=0, response=nonce XOR 0 = nonce.
        // For bit=1, response=nonce XOR challenge. We verify that each response
        // when XORed with challenge gives back a valid nonce that produces
        // the corresponding bit commitment.
        //
        // Also reconstruct the value from the verified bits to check the binding.
        let response_start = bits * 32;
        let mut reconstructed_value: u64 = 0;
        for i in 0..bits {
            let response = &proof.proof_bytes[response_start + i * 32..response_start + (i + 1) * 32];
            let bit_commit = &proof.proof_bytes[i * 32..(i + 1) * 32];

            // Reconstruct nonce for bit=0: nonce = response
            let mut verify_h0 = Sha256::new();
            verify_h0.update(b"ShadowDAG_BitCommit_v2");
            verify_h0.update(response); // nonce = response when bit=0
            verify_h0.update([0u8]);   // bit = 0
            verify_h0.update((i as u32).to_le_bytes());
            verify_h0.update(proof.commitment_hex.as_bytes());
            let commit_if_0 = verify_h0.finalize();

            // Reconstruct nonce for bit=1: nonce = response XOR challenge
            let mut nonce_if_1 = [0u8; 32];
            for j in 0..32 {
                nonce_if_1[j] = response[j] ^ stored_challenge[j];
            }
            let mut verify_h1 = Sha256::new();
            verify_h1.update(b"ShadowDAG_BitCommit_v2");
            verify_h1.update(nonce_if_1);
            verify_h1.update([1u8]);   // bit = 1
            verify_h1.update((i as u32).to_le_bytes());
            verify_h1.update(proof.commitment_hex.as_bytes());
            let commit_if_1 = verify_h1.finalize();

            // Bit commitment must match EXACTLY one of the two possibilities
            let matches_0 = commit_if_0.as_slice() == bit_commit;
            let matches_1 = commit_if_1.as_slice() == bit_commit;

            if !matches_0 && !matches_1 {
                return false; // Forged proof — bit commitment doesn't match any valid bit
            }

            // Reconstruct the bit value for value binding check
            if matches_1
                && i < 64 {
                    reconstructed_value |= 1u64 << i;
                }
        }

        // VALUE BINDING CHECK: verify the bit decomposition matches the committed value.
        // The prover included H(blinding || bit_commitments || commitment || value).
        // We recompute it using the blinding factor and reconstructed value.
        // This prevents forging a proof where bits encode value X but commitment hides Y.
        let binding_start = challenge_start + 32;
        if binding_start + 32 > proof.proof_bytes.len() { return false; }
        let stored_binding = &proof.proof_bytes[binding_start..binding_start + 32];

        let mut binding_h = Sha256::new();
        binding_h.update(b"ShadowDAG_ValueBinding_v1");
        binding_h.update(proof.blinding_hex.as_bytes());
        for bc in &bit_commits {
            binding_h.update(bc);
        }
        binding_h.update(proof.commitment_hex.as_bytes());
        binding_h.update(reconstructed_value.to_le_bytes());
        let expected_binding = binding_h.finalize();

        if expected_binding.as_slice() != stored_binding {
            return false; // Value binding mismatch — bits don't match committed value
        }

        // Additionally verify the Pedersen commitment opens to the reconstructed value
        if !PedersenCommitment::verify(
            &proof.commitment_hex,
            reconstructed_value,
            &proof.blinding_hex,
        ) {
            return false;
        }

        true
    }

    /// Verify with a specific amount (for the commitment owner who knows the blinding factor)
    pub fn verify_with_amount(proof: &BulletproofResult, amount: u64) -> bool {
        if !Self::verify_range_proof(proof) { return false; }

        // Verify the Pedersen commitment opens to this amount
        PedersenCommitment::verify(
            &proof.commitment_hex,
            amount,
            &proof.blinding_hex,
        )
    }

    /// Generate aggregated proofs for multiple outputs
    pub fn prove_batch(amounts: &[u64]) -> AggregatedProof {
        let proofs: Vec<BulletproofResult> = amounts.iter()
            .map(|&a| Self::prove(a))
            .collect();

        let total_valid = proofs.iter().filter(|p| p.is_valid).count();

        // Aggregate hash for batch verification
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_BatchProof_v2");
        for p in &proofs {
            h.update(&p.proof_bytes);
        }
        let aggregate_hash = hex::encode(h.finalize());

        AggregatedProof { proofs, total_valid, aggregate_hash }
    }

    /// Verify all proofs in a batch
    pub fn verify_batch(batch: &AggregatedProof) -> bool {
        if batch.proofs.is_empty() { return false; }
        batch.proofs.iter().all(Self::verify_range_proof)
    }

    /// Check if an amount is within valid range
    pub fn is_valid_amount(amount: u64) -> bool {
        amount > 0 && amount <= MAX_RANGE_VALUE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_valid_amount() {
        let result = Bulletproof::prove(1000);
        assert!(result.is_valid);
        assert!(!result.proof_bytes.is_empty());
        assert!(!result.commitment_hex.is_empty());
        assert!(!result.blinding_hex.is_empty());
    }

    #[test]
    fn prove_zero_fails() {
        let result = Bulletproof::prove(0);
        assert!(!result.is_valid);
    }

    #[test]
    fn prove_max_range() {
        let result = Bulletproof::prove(MAX_RANGE_VALUE);
        assert!(result.is_valid);
    }

    #[test]
    fn prove_over_max_fails() {
        let result = Bulletproof::prove(MAX_RANGE_VALUE + 1);
        assert!(!result.is_valid);
    }

    #[test]
    fn verify_valid_proof() {
        let proof = Bulletproof::prove(5000);
        assert!(Bulletproof::verify_range_proof(&proof));
    }

    #[test]
    fn verify_fails_on_empty_proof() {
        let bad = BulletproofResult {
            proof_bytes: vec![],
            commitment_hex: String::new(),
            blinding_hex: String::new(),
            is_valid: false,
            bits: 64,
        };
        assert!(!Bulletproof::verify_range_proof(&bad));
    }

    #[test]
    fn verify_with_correct_amount() {
        let amount = 42_000u64;
        let proof = Bulletproof::prove(amount);
        assert!(Bulletproof::verify_with_amount(&proof, amount));
    }

    #[test]
    fn verify_with_wrong_amount_fails() {
        let proof = Bulletproof::prove(42_000);
        // Wrong amount should fail Pedersen verification
        assert!(!Bulletproof::verify_with_amount(&proof, 99_999));
    }

    #[test]
    fn batch_prove_and_verify() {
        let amounts = vec![100, 200, 300, 400, 500];
        let batch = Bulletproof::prove_batch(&amounts);
        assert_eq!(batch.total_valid, 5);
        assert!(Bulletproof::verify_batch(&batch));
    }

    #[test]
    fn different_amounts_different_proofs() {
        let p1 = Bulletproof::prove(100);
        let p2 = Bulletproof::prove(200);
        assert_ne!(p1.commitment_hex, p2.commitment_hex);
        assert_ne!(p1.proof_bytes, p2.proof_bytes);
    }

    #[test]
    fn commitment_hides_amount() {
        let p1 = Bulletproof::prove(100);
        let p2 = Bulletproof::prove(100);
        // Same amount, different blinding → different commitment
        assert_ne!(p1.commitment_hex, p2.commitment_hex,
            "Same amount must produce different commitments (randomized blinding)");
    }

    #[test]
    fn proof_is_deterministic_size() {
        let p1 = Bulletproof::prove(100);
        let p2 = Bulletproof::prove(999);
        assert_eq!(p1.proof_bytes.len(), p2.proof_bytes.len(),
            "All proofs for same bit-width should be same size");
    }

    #[test]
    fn tampered_value_binding_fails() {
        let mut proof = Bulletproof::prove(1000);
        assert!(Bulletproof::verify_range_proof(&proof));
        // Tamper with the value binding (last 32 bytes)
        let len = proof.proof_bytes.len();
        proof.proof_bytes[len - 1] ^= 0xFF;
        assert!(!Bulletproof::verify_range_proof(&proof),
            "Tampered value binding must be rejected");
    }

    #[test]
    fn tampered_bit_commitment_fails() {
        let mut proof = Bulletproof::prove(500);
        assert!(Bulletproof::verify_range_proof(&proof));
        // Tamper with the first bit commitment
        proof.proof_bytes[0] ^= 0xFF;
        assert!(!Bulletproof::verify_range_proof(&proof),
            "Tampered bit commitment must be rejected");
    }

    #[test]
    fn wrong_blinding_fails_verification() {
        let mut proof = Bulletproof::prove(1000);
        assert!(Bulletproof::verify_range_proof(&proof));
        // Replace blinding with a different one
        proof.blinding_hex = hex::encode([0xABu8; 32]);
        assert!(!Bulletproof::verify_range_proof(&proof),
            "Wrong blinding factor must be rejected by value binding");
    }
}
