// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Range Proof using Borromean Ring Signatures on bit decomposition.
//
// Proves that a Pedersen commitment C = v*H + r*G hides a value v in [0, 2^64)
// without revealing v.
//
// Approach:
//   1. Decompose v into 64 bits: v = sum(b_i * 2^i)
//   2. Create a sub-commitment for each bit: C_i = b_i*H + r_i*G
//   3. For each bit, create a Borromean ring signature proving b_i in {0, 1}
//   4. Verify sum of weighted bit-commitments equals the original commitment
//
// The blinding factors r_i are chosen so that sum(r_i) == r (the original
// blinding), which ensures sum(2^i * C_i) == C.
// ═══════════════════════════════════════════════════════════════════════════

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use super::pedersen::generator_h;

/// Number of bits in the range proof (proves value in [0, 2^RANGE_BITS)).
pub const RANGE_BITS: usize = 64;

/// A range proof proving a Pedersen commitment hides a value in [0, 2^64).
///
/// Uses bit decomposition with Borromean ring signatures:
/// - `bit_commitments`: one Pedersen sub-commitment per bit
/// - `challenges`: the initial challenge for each bit's ring signature
/// - `responses`: two response scalars per bit (one for the 0-branch, one for the 1-branch)
pub struct RangeProof {
    pub bit_commitments: Vec<RistrettoPoint>,
    pub challenges: Vec<Scalar>,
    pub responses: Vec<[Scalar; 2]>,
}

/// Create a range proof for a value committed with a given blinding factor.
///
/// The commitment must be `C = value*H + blinding*G` using the same `generator_h()`.
pub fn prove(value: u64, blinding: &Scalar) -> RangeProof {
    use rand::rngs::OsRng;
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = generator_h();

    let mut bit_commitments = Vec::with_capacity(RANGE_BITS);
    let mut bit_blindings = Vec::with_capacity(RANGE_BITS);
    let mut challenges = Vec::with_capacity(RANGE_BITS);
    let mut responses = Vec::with_capacity(RANGE_BITS);

    // Split blinding factor across bits: sum(2^i * r_i) == blinding
    // This is required because the verifier checks sum(2^i * C_i) == C,
    // and C_i = b_i*H + r_i*G, so we need sum(2^i * r_i) == r.
    let mut remaining_blinding = *blinding;

    for i in 0..RANGE_BITS {
        let bit = (value >> i) & 1;

        // Choose per-bit blinding. Last bit gets the remainder (scaled by 2^-i).
        let r_i = if i < RANGE_BITS - 1 {
            let r = Scalar::random(&mut OsRng);
            let weight = Scalar::from(1u64 << i);
            remaining_blinding -= weight * r;
            r
        } else {
            // Last bit: r_{63} = remaining_blinding / 2^63
            let weight_inv = Scalar::from(1u64 << i).invert();
            remaining_blinding * weight_inv
        };

        // Bit sub-commitment: C_i = bit*H + r_i*G
        let c_i = Scalar::from(bit) * h + r_i * g;
        bit_commitments.push(c_i);
        bit_blindings.push(r_i);

        // Borromean ring signature proving bit in {0, 1}.
        //
        // Ring has two members:
        //   Key0 = C_i        (commits to 0 if bit==0)
        //   Key1 = C_i - H    (commits to 0 if bit==1, since C_i - 1*H = r_i*G)
        //
        // The real key is the one where we know the discrete log r_i (w.r.t. G).
        let alpha = Scalar::random(&mut OsRng);

        if bit == 0 {
            // Real branch is 0 (C_i = 0*H + r_i*G = r_i*G, so we know DL).
            // Simulate branch 1.
            let s1 = Scalar::random(&mut OsRng);

            // L0 = alpha * G (real nonce commitment)
            let l0 = alpha * g;

            // Challenge for branch 1: e1 = H(domain || i || L0)
            let e1 = bit_challenge(i, &l0);

            // Simulated L1 for branch 1: L1 = s1*G + e1*(C_i - H)
            let l1 = s1 * g + e1 * (c_i - h);

            // Challenge wrapping back to branch 0: e0 = H(domain || i || L1)
            let e0 = bit_challenge(i, &l1);

            // Response for real branch: s0 = alpha - e0 * r_i
            let s0 = alpha - e0 * r_i;

            challenges.push(e0);
            responses.push([s0, s1]);
        } else {
            // Real branch is 1 (C_i - H = r_i*G, so we know DL).
            // Simulate branch 0.
            let s0 = Scalar::random(&mut OsRng);

            // L1 = alpha * G (real nonce commitment)
            let l1 = alpha * g;

            // Challenge wrapping: e0 = H(domain || i || L1)
            let e0 = bit_challenge(i, &l1);

            // Simulated L0 for branch 0: L0 = s0*G + e0*C_i
            let l0 = s0 * g + e0 * c_i;

            // Challenge for branch 1: e1 = H(domain || i || L0)
            let e1 = bit_challenge(i, &l0);

            // Response for real branch: s1 = alpha - e1 * r_i
            let s1 = alpha - e1 * r_i;

            challenges.push(e0);
            responses.push([s0, s1]);
        }
    }

    RangeProof {
        bit_commitments,
        challenges,
        responses,
    }
}

/// Verify a range proof against a commitment.
///
/// Checks:
/// 1. Structural validity (correct number of elements)
/// 2. Bit decomposition: sum(2^i * C_i) == commitment
/// 3. Each Borromean ring signature is valid (each bit is 0 or 1)
pub fn verify(commitment: &RistrettoPoint, proof: &RangeProof) -> bool {
    if proof.bit_commitments.len() != RANGE_BITS {
        return false;
    }
    if proof.challenges.len() != RANGE_BITS {
        return false;
    }
    if proof.responses.len() != RANGE_BITS {
        return false;
    }

    let g = RISTRETTO_BASEPOINT_POINT;
    let h = generator_h();

    // Check 1: weighted sum of bit-commitments must equal the original commitment.
    // sum(2^i * C_i) should equal C = v*H + r*G because:
    //   sum(2^i * (b_i*H + r_i*G)) = (sum(2^i * b_i))*H + (sum(r_i))*G = v*H + r*G
    let identity = Scalar::ZERO * g;
    let mut reconstructed = identity;
    for i in 0..RANGE_BITS {
        // Compute 2^i as a scalar. For i < 64 we can use bit shifting.
        let weight = if i < 64 {
            Scalar::from(1u64 << i)
        } else {
            // Should not happen with RANGE_BITS == 64, but be safe
            return false;
        };
        reconstructed += weight * proof.bit_commitments[i];
    }

    if reconstructed != *commitment {
        return false;
    }

    // Check 2: each Borromean ring signature proves its bit is in {0, 1}.
    for i in 0..RANGE_BITS {
        let c_i = proof.bit_commitments[i];
        let e0 = proof.challenges[i];
        let [s0, s1] = proof.responses[i];

        // Recompute the ring:
        // Branch 0 (bit=0): L0 = s0*G + e0*C_i
        let l0 = s0 * g + e0 * c_i;

        // Challenge for branch 1
        let e1 = bit_challenge(i, &l0);

        // Branch 1 (bit=1): L1 = s1*G + e1*(C_i - H)
        let l1 = s1 * g + e1 * (c_i - h);

        // Challenge must wrap back to e0
        let e0_check = bit_challenge(i, &l1);

        if e0_check != e0 {
            return false;
        }
    }

    true
}

/// Domain-separated challenge hash for a single bit's ring signature.
fn bit_challenge(bit_index: usize, point: &RistrettoPoint) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"ShadowDAG_range_v1");
    hasher.update(bit_index.to_le_bytes());
    hasher.update(point.compress().as_bytes());
    Scalar::from_hash(hasher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::privacy::confidential::pedersen::RealPedersenCommitment;

    #[test]
    fn prove_and_verify_zero() {
        let c = RealPedersenCommitment::commit_random(0);
        let proof = prove(0, &c.blinding);
        assert!(
            verify(&c.commitment, &proof),
            "Range proof must verify for value 0"
        );
    }

    #[test]
    fn prove_and_verify_one() {
        let c = RealPedersenCommitment::commit_random(1);
        let proof = prove(1, &c.blinding);
        assert!(
            verify(&c.commitment, &proof),
            "Range proof must verify for value 1"
        );
    }

    #[test]
    fn prove_and_verify_42() {
        let c = RealPedersenCommitment::commit_random(42);
        let proof = prove(42, &c.blinding);
        assert!(
            verify(&c.commitment, &proof),
            "Range proof must verify for value 42"
        );
    }

    #[test]
    fn prove_and_verify_large_value() {
        let value = 1_000_000_000u64;
        let c = RealPedersenCommitment::commit_random(value);
        let proof = prove(value, &c.blinding);
        assert!(
            verify(&c.commitment, &proof),
            "Range proof must verify for large value"
        );
    }

    #[test]
    fn prove_and_verify_max() {
        let c = RealPedersenCommitment::commit_random(u64::MAX);
        let proof = prove(u64::MAX, &c.blinding);
        assert!(
            verify(&c.commitment, &proof),
            "Range proof must verify for u64::MAX"
        );
    }

    #[test]
    fn verify_fails_with_wrong_commitment() {
        let c = RealPedersenCommitment::commit_random(42);
        let proof = prove(42, &c.blinding);

        // Create a different commitment
        let wrong = RealPedersenCommitment::commit_random(99);
        assert!(
            !verify(&wrong.commitment, &proof),
            "Range proof must fail against wrong commitment"
        );
    }

    #[test]
    fn verify_fails_with_tampered_challenge() {
        use rand::rngs::OsRng;
        let c = RealPedersenCommitment::commit_random(100);
        let mut proof = prove(100, &c.blinding);

        // Tamper with a challenge
        proof.challenges[0] = Scalar::random(&mut OsRng);
        assert!(
            !verify(&c.commitment, &proof),
            "Tampered challenge must cause verification failure"
        );
    }

    #[test]
    fn verify_fails_with_tampered_response() {
        use rand::rngs::OsRng;
        let c = RealPedersenCommitment::commit_random(100);
        let mut proof = prove(100, &c.blinding);

        // Tamper with a response
        proof.responses[0][0] = Scalar::random(&mut OsRng);
        assert!(
            !verify(&c.commitment, &proof),
            "Tampered response must cause verification failure"
        );
    }

    #[test]
    fn confidential_transaction_balance() {
        // Full confidential transaction test:
        // Input: 1000, Outputs: 700 + 200, Fee: 100
        use rand::rngs::OsRng;

        let r_in = Scalar::random(&mut OsRng);
        let r_out1 = Scalar::random(&mut OsRng);
        let r_out2 = r_in - r_out1; // blinding must balance

        let c_in = RealPedersenCommitment::commit(1000, r_in);
        let c_out1 = RealPedersenCommitment::commit(700, r_out1);
        let c_out2 = RealPedersenCommitment::commit(200, r_out2);

        // Range proofs for each output
        let proof1 = prove(700, &r_out1);
        let proof2 = prove(200, &r_out2);

        // Verify range proofs
        assert!(verify(&c_out1.commitment, &proof1), "Output 1 range proof");
        assert!(verify(&c_out2.commitment, &proof2), "Output 2 range proof");

        // Verify balance
        assert!(
            RealPedersenCommitment::verify_balance(
                &[c_in.commitment],
                &[c_out1.commitment, c_out2.commitment],
                100,
            ),
            "Transaction balance must verify"
        );
    }
}
