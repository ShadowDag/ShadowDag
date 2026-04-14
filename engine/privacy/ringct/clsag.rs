//! CLSAG (Compact Linkable Spontaneous Anonymous Group) ring signatures
//!
//! Uses real elliptic curve cryptography via curve25519-dalek Ristretto points.
//!
//! Key properties:
//! - Proves knowledge of one private key in a ring without revealing which
//! - Linkable: same key used twice produces the same Key Image (prevents double-spend)
//! - Key Image: I = x * H_p(P) where H_p is hash-to-point

use crate::errors::CryptoError;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// A CLSAG ring signature.
pub struct CLSAGSignature {
    /// Initial challenge scalar
    pub c0: Scalar,
    /// Response scalars (one per ring member)
    pub s: Vec<Scalar>,
    /// Key image (linkability tag), compressed
    pub key_image: CompressedRistretto,
}

/// Hash-to-point: maps a public key to a curve point (for key image computation).
fn hash_to_point(pubkey: &RistrettoPoint) -> RistrettoPoint {
    let hash = Sha512::digest(pubkey.compress().as_bytes());
    RistrettoPoint::from_uniform_bytes(&hash.into())
}

/// Generate key image: I = x * H_p(P) where P = x*G.
pub fn key_image(secret_key: &Scalar, public_key: &RistrettoPoint) -> RistrettoPoint {
    let hp = hash_to_point(public_key);
    secret_key * hp
}

/// Compute challenge hash for CLSAG.
fn challenge_hash(
    message: &[u8],
    l_point: &RistrettoPoint, // L = s*G + c*P
    r_point: &RistrettoPoint, // R = s*H_p(P) + c*I
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"CLSAG_challenge_v1");
    hasher.update(message);
    hasher.update(l_point.compress().as_bytes());
    hasher.update(r_point.compress().as_bytes());
    Scalar::from_hash(hasher)
}

/// Create a CLSAG ring signature.
///
/// # Arguments
/// - `message`: the data being signed
/// - `ring`: public keys of all ring members
/// - `secret_index`: index of the real signer within the ring
/// - `secret_key`: signer's private key
///
/// # Errors
/// Returns `CryptoError::InvalidRingIndex` if `secret_index >= ring.len()`.
pub fn sign(
    message: &[u8],
    ring: &[RistrettoPoint],
    secret_index: usize,
    secret_key: &Scalar,
) -> Result<CLSAGSignature, CryptoError> {
    use rand::rngs::OsRng;

    let n = ring.len();
    if secret_index >= n {
        return Err(CryptoError::InvalidRingIndex {
            index: secret_index,
            ring_size: n,
        });
    }

    let g = RISTRETTO_BASEPOINT_POINT;
    let ki = key_image(secret_key, &ring[secret_index]);

    // Step 1: Generate random alpha for the signer's position
    let alpha = Scalar::random(&mut OsRng);

    // Compute L = alpha * G, R = alpha * H_p(P_s)
    let hp_s = hash_to_point(&ring[secret_index]);
    let l = alpha * g;
    let r = alpha * hp_s;

    let mut c = vec![Scalar::ZERO; n];
    let mut s = vec![Scalar::ZERO; n];

    // Step 2: Compute challenges for all positions using constant-time iteration.
    // Always iterate from index 0 through n-1 to avoid timing leaks from
    // signer_position-dependent loop bounds or access patterns (issue #25).

    // Seed the challenge at (secret_index + 1) % n from the signer's commitment
    c[(secret_index + 1) % n] = challenge_hash(message, &l, &r);

    // Generate random response scalars for every non-signer position.
    // We generate for ALL positions uniformly and overwrite the signer's later.
    for item in s.iter_mut().take(n) {
        *item = Scalar::random(&mut OsRng);
    }

    // Propagate challenges: always iterate exactly n-1 steps starting from
    // position (secret_index + 1), processing every non-signer ring member.
    // The loop count is constant (n-1) regardless of secret_index.
    for step in 0..(n - 1) {
        let idx = (secret_index + 1 + step) % n;
        let next_idx = (idx + 1) % n;

        let hp_idx = hash_to_point(&ring[idx]);

        let l_i = s[idx] * g + c[idx] * ring[idx];
        let r_i = s[idx] * hp_idx + c[idx] * ki;

        c[next_idx] = challenge_hash(message, &l_i, &r_i);
    }

    // Step 3: Close the ring — s[pi] = alpha - c[pi] * x
    s[secret_index] = alpha - c[secret_index] * secret_key;

    Ok(CLSAGSignature {
        c0: c[0],
        s,
        key_image: ki.compress(),
    })
}

/// Verify a CLSAG ring signature.
///
/// Returns `true` if the signature is valid for the given message and ring.
#[allow(clippy::needless_range_loop)]
pub fn verify(message: &[u8], ring: &[RistrettoPoint], sig: &CLSAGSignature) -> bool {
    let n = ring.len();
    // Reject empty rings — otherwise the loop never runs and c == c0 trivially
    if n == 0 {
        return false;
    }
    if sig.s.len() != n {
        return false;
    }

    let g = RISTRETTO_BASEPOINT_POINT;
    let ki = match sig.key_image.decompress() {
        Some(p) => p,
        None => return false,
    };

    let mut c = sig.c0;

    for i in 0..n {
        let hp = hash_to_point(&ring[i]);
        let l = sig.s[i] * g + c * ring[i];
        let r = sig.s[i] * hp + c * ki;
        c = challenge_hash(message, &l, &r);
    }

    // Ring closes if final c equals c0
    c == sig.c0
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Helper: generate a keypair (secret scalar, public Ristretto point).
    fn gen_keypair() -> (Scalar, RistrettoPoint) {
        let sk = Scalar::random(&mut OsRng);
        let pk = sk * RISTRETTO_BASEPOINT_POINT;
        (sk, pk)
    }

    /// Helper: build a ring of `n` keys, returning all keypairs and the ring of public keys.
    fn build_ring(n: usize) -> (Vec<(Scalar, RistrettoPoint)>, Vec<RistrettoPoint>) {
        let pairs: Vec<_> = (0..n).map(|_| gen_keypair()).collect();
        let ring: Vec<_> = pairs.iter().map(|(_, pk)| *pk).collect();
        (pairs, ring)
    }

    #[test]
    fn sign_verify_ring_size_1() {
        let (pairs, ring) = build_ring(1);
        let msg = b"ring size 1";
        let sig = sign(msg, &ring, 0, &pairs[0].0).unwrap();
        assert!(verify(msg, &ring, &sig));
    }

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn sign_verify_ring_size_4() {
        let (pairs, ring) = build_ring(4);
        let msg = b"ring size 4";
        for signer in 0..4 {
            let sig = sign(msg, &ring, signer, &pairs[signer].0).unwrap();
            assert!(verify(msg, &ring, &sig), "failed for signer index {signer}");
        }
    }

    #[test]
    fn sign_verify_ring_size_11() {
        let (pairs, ring) = build_ring(11);
        let msg = b"ring size 11";
        let sig = sign(msg, &ring, 7, &pairs[7].0).unwrap();
        assert!(verify(msg, &ring, &sig));
    }

    #[test]
    fn verify_fails_wrong_message() {
        let (pairs, ring) = build_ring(4);
        let sig = sign(b"correct message", &ring, 2, &pairs[2].0).unwrap();
        assert!(!verify(b"wrong message", &ring, &sig));
    }

    #[test]
    fn verify_fails_modified_s() {
        let (pairs, ring) = build_ring(4);
        let msg = b"tamper test";
        let mut sig = sign(msg, &ring, 1, &pairs[1].0).unwrap();
        // Flip one response scalar
        sig.s[0] += Scalar::ONE;
        assert!(!verify(msg, &ring, &sig));
    }

    #[test]
    fn sign_rejects_out_of_range_index() {
        let (pairs, ring) = build_ring(4);
        let result = sign(b"bad index", &ring, 999, &pairs[0].0);
        assert!(result.is_err());
    }

    #[test]
    fn key_image_consistent_for_same_key() {
        let (sk, pk) = gen_keypair();
        let ki1 = key_image(&sk, &pk);
        let ki2 = key_image(&sk, &pk);
        assert_eq!(ki1, ki2);
    }

    #[test]
    fn key_image_differs_for_different_keys() {
        let (sk1, pk1) = gen_keypair();
        let (sk2, pk2) = gen_keypair();
        let ki1 = key_image(&sk1, &pk1);
        let ki2 = key_image(&sk2, &pk2);
        assert_ne!(ki1, ki2);
    }
}
