// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Real Pedersen Commitments using Ristretto (curve25519-dalek).
//
// A Pedersen commitment C = v*H + r*G is:
//   - Perfectly hiding: without knowing r, commitment reveals nothing about v
//   - Computationally binding: cannot find (v', r') != (v, r) with same C
//   - Additively homomorphic: C(a, r1) + C(b, r2) == C(a+b, r1+r2)
//
// Generator H is a nothing-up-my-sleeve point derived by hashing a fixed
// domain separator, ensuring nobody knows the discrete log of H w.r.t. G.
// ═══════════════════════════════════════════════════════════════════════════

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Second generator H (nothing-up-my-sleeve point).
///
/// Derived deterministically so nobody knows log_G(H).
pub fn generator_h() -> RistrettoPoint {
    let hash = Sha512::digest(b"ShadowDAG_Pedersen_H_v1");
    RistrettoPoint::from_uniform_bytes(&hash.into())
}

/// A Pedersen commitment with its opening information.
///
/// The commitment is `C = v*H + r*G` where:
/// - `v` is the committed value
/// - `r` is the blinding factor (random scalar)
/// - `H` is the nothing-up-my-sleeve generator
/// - `G` is the Ristretto basepoint
pub struct RealPedersenCommitment {
    /// The commitment point on the curve
    pub commitment: RistrettoPoint,
    /// The committed value (secret — only known to creator)
    pub value: u64,
    /// The blinding factor (secret — only known to creator)
    pub blinding: Scalar,
}

impl RealPedersenCommitment {
    /// Create a commitment to `value` with a specific blinding factor.
    pub fn commit(value: u64, blinding: Scalar) -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let v = Scalar::from(value);
        let commitment = v * h + blinding * g;
        Self {
            commitment,
            value,
            blinding,
        }
    }

    /// Create a commitment to `value` with a random blinding factor.
    pub fn commit_random(value: u64) -> Self {
        use rand::rngs::OsRng;
        let blinding = Scalar::random(&mut OsRng);
        Self::commit(value, blinding)
    }

    /// Verify that a commitment opens to the given value and blinding factor.
    ///
    /// Anyone who knows (value, blinding) can verify the opening.
    pub fn verify_opening(
        commitment: &RistrettoPoint,
        value: u64,
        blinding: &Scalar,
    ) -> bool {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let v = Scalar::from(value);
        let expected = v * h + blinding * g;
        *commitment == expected
    }

    /// Verify conservation of value across a transaction.
    ///
    /// For a valid transaction: sum(inputs) == sum(outputs) + fee
    ///
    /// The fee commitment uses zero blinding because the fee is public.
    /// This works because Pedersen commitments are additively homomorphic:
    ///   C(a, r1) + C(b, r2) = C(a+b, r1+r2)
    ///
    /// The sum of input blindings must equal the sum of output blindings
    /// for the balance to hold (the prover ensures this when constructing
    /// the transaction).
    pub fn verify_balance(
        input_commitments: &[RistrettoPoint],
        output_commitments: &[RistrettoPoint],
        fee: u64,
    ) -> bool {
        let h = generator_h();

        // Identity point via 0 * G
        let identity = Scalar::ZERO * RISTRETTO_BASEPOINT_POINT;

        let sum_inputs: RistrettoPoint = input_commitments
            .iter()
            .copied()
            .fold(identity, |acc, p| acc + p);

        let sum_outputs: RistrettoPoint = output_commitments
            .iter()
            .copied()
            .fold(identity, |acc, p| acc + p);

        // Fee commitment has zero blinding factor (fee is public)
        let fee_commitment = Scalar::from(fee) * h;

        sum_inputs == sum_outputs + fee_commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_and_verify_opening() {
        let value = 42u64;
        let c = RealPedersenCommitment::commit_random(value);
        assert!(
            RealPedersenCommitment::verify_opening(&c.commitment, value, &c.blinding),
            "Opening verification must pass for correct value and blinding"
        );
    }

    #[test]
    fn wrong_value_fails_verification() {
        let c = RealPedersenCommitment::commit_random(100);
        assert!(
            !RealPedersenCommitment::verify_opening(&c.commitment, 101, &c.blinding),
            "Opening verification must fail for wrong value"
        );
    }

    #[test]
    fn wrong_blinding_fails_verification() {
        use rand::rngs::OsRng;
        let c = RealPedersenCommitment::commit_random(100);
        let wrong_blinding = Scalar::random(&mut OsRng);
        assert!(
            !RealPedersenCommitment::verify_opening(&c.commitment, 100, &wrong_blinding),
            "Opening verification must fail for wrong blinding factor"
        );
    }

    #[test]
    fn balance_verification_passes() {
        // Transaction: input 1000 = output 700 + output 200 + fee 100
        use rand::rngs::OsRng;
        let r_in = Scalar::random(&mut OsRng);
        let r_out1 = Scalar::random(&mut OsRng);
        // Blinding must balance: r_in == r_out1 + r_out2
        let r_out2 = r_in - r_out1;

        let c_in = RealPedersenCommitment::commit(1000, r_in);
        let c_out1 = RealPedersenCommitment::commit(700, r_out1);
        let c_out2 = RealPedersenCommitment::commit(200, r_out2);
        let fee = 100u64;

        assert!(
            RealPedersenCommitment::verify_balance(
                &[c_in.commitment],
                &[c_out1.commitment, c_out2.commitment],
                fee,
            ),
            "Balance must verify when sum(inputs) == sum(outputs) + fee"
        );
    }

    #[test]
    fn balance_verification_fails_on_inflation() {
        use rand::rngs::OsRng;
        let r_in = Scalar::random(&mut OsRng);
        let r_out = Scalar::random(&mut OsRng);

        let c_in = RealPedersenCommitment::commit(100, r_in);
        // Attempt to create more value than input
        let c_out = RealPedersenCommitment::commit(200, r_out);

        assert!(
            !RealPedersenCommitment::verify_balance(
                &[c_in.commitment],
                &[c_out.commitment],
                0,
            ),
            "Balance must fail when outputs exceed inputs (inflation attempt)"
        );
    }

    #[test]
    fn homomorphic_property() {
        // C(a, r1) + C(b, r2) == C(a+b, r1+r2)
        use rand::rngs::OsRng;
        let r1 = Scalar::random(&mut OsRng);
        let r2 = Scalar::random(&mut OsRng);

        let c1 = RealPedersenCommitment::commit(30, r1);
        let c2 = RealPedersenCommitment::commit(12, r2);
        let c_sum = RealPedersenCommitment::commit(42, r1 + r2);

        assert_eq!(
            c1.commitment + c2.commitment,
            c_sum.commitment,
            "Pedersen commitments must be additively homomorphic"
        );
    }

    #[test]
    fn same_value_different_blinding_produces_different_commitments() {
        let c1 = RealPedersenCommitment::commit_random(100);
        let c2 = RealPedersenCommitment::commit_random(100);
        assert_ne!(
            c1.commitment, c2.commitment,
            "Same value with different blinding must produce different commitments (hiding)"
        );
    }

    #[test]
    fn deterministic_with_same_blinding() {
        let blinding = Scalar::from(999u64);
        let c1 = RealPedersenCommitment::commit(50, blinding);
        let c2 = RealPedersenCommitment::commit(50, blinding);
        assert_eq!(
            c1.commitment, c2.commitment,
            "Same value and blinding must produce identical commitments"
        );
    }
}
