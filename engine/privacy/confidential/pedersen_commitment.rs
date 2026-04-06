// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use sha2::{Sha512, Digest};
use rand::rngs::OsRng;
use crate::errors::CryptoError;

pub struct CommitmentResult {
    pub commitment_hex: String,
    pub blinding_hex:   String,
    pub is_valid:       bool,
}

pub struct PedersenCommitment;

impl PedersenCommitment {
    pub fn commit(amount: u64) -> String {
        let result = Self::commit_with_blinding(amount);
        result.commitment_hex
    }

    pub fn commit_with_blinding(amount: u64) -> CommitmentResult {
        let v = Scalar::from(amount);

        let r = Scalar::random(&mut OsRng);

        let h_point = Self::_h_point();

        let commitment: RistrettoPoint =
            v * RISTRETTO_BASEPOINT_POINT + r * h_point;

        let compressed     = commitment.compress();
        let commitment_hex = hex::encode(compressed.as_bytes());
        let blinding_hex   = hex::encode(r.as_bytes());

        CommitmentResult {
            commitment_hex,
            blinding_hex,
            is_valid: true,
        }
    }

    pub fn verify(commitment_hex: &str, amount: u64, blinding_hex: &str) -> bool {
        let v     = Scalar::from(amount);
        let r_bytes = match hex::decode(blinding_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let mut r_arr = [0u8; 32];
        r_arr.copy_from_slice(&r_bytes);

        // Check for canonical scalar (r < L) to prevent inflation attacks
        if !Self::check_canonical_scalar(&r_arr) {
            return false; // Non-canonical scalar rejected
        }

        let r = Scalar::from_canonical_bytes(r_arr).unwrap();

        let h_point     = Self::_h_point();
        let expected: RistrettoPoint = v * RISTRETTO_BASEPOINT_POINT + r * h_point;
        let expected_hex = hex::encode(expected.compress().as_bytes());

        
        expected_hex == commitment_hex
    }

    pub fn add_commitments(c1_hex: &str, c2_hex: &str) -> Option<String> {
        let p1 = Self::_from_hex(c1_hex)?;
        let p2 = Self::_from_hex(c2_hex)?;
        let sum = p1 + p2;
        Some(hex::encode(sum.compress().as_bytes()))
    }

    fn _h_point() -> RistrettoPoint {
        let mut hasher = Sha512::new();
        hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
        hasher.update(b"ShadowDAG_H_point_v1");
        let hash = hasher.finalize();
        RistrettoPoint::from_uniform_bytes(&hash.into())
    }

    /// Check for canonical scalar (r < L) to prevent inflation attacks.
    /// Scalar is canonical if from_canonical_bytes succeeds.
    fn check_canonical_scalar(bytes: &[u8; 32]) -> bool {
        Scalar::from_canonical_bytes(*bytes).is_some()
    }

    /// Derive a deterministic blinding factor from master secret and output context.
    /// This allows recovery from seed backup.
    ///
    /// Returns `CryptoError::NonCanonicalScalar` if the derived hash is not a
    /// canonical scalar (i.e. >= the curve group order L).  This rejects the
    /// ~0.4 % of inputs that `from_bytes_mod_order` would silently reduce,
    /// eliminating the inflation risk from non-canonical scalars.
    pub fn deterministic_blinding(master_secret: &[u8], amount: u64, output_index: u32) -> Result<Scalar, CryptoError> {
        use sha2::{Sha256, Digest as _};
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_Blinding_v2");
        h.update(master_secret);
        h.update(&amount.to_le_bytes());
        h.update(&output_index.to_le_bytes());
        let hash: [u8; 32] = h.finalize().into();
        Scalar::from_canonical_bytes(hash)
            .ok_or(CryptoError::NonCanonicalScalar)
    }

    fn _from_hex(hex_str: &str) -> Option<RistrettoPoint> {
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 32 { return None; }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        CompressedRistretto(arr).decompress()
    }
}
