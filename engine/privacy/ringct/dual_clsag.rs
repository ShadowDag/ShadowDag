// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Dual-key CLSAG ring signatures over Ristretto.
//!
//! Proves, in a single signature, knowledge of (a) a spend key `p` for one ring
//! member's public key and (b) a blinding offset `z` such that that member's
//! commitment minus the per-input pseudo-output commitment equals `z·G`. This
//! binds the spent amount, enabling RingCT confidential amounts.
//!
//! Construction: standard CLSAG (aggregation coefficients μ_P/μ_C, key images
//! I and D). Ristretto removes cofactor/torsion handling. SECURITY: external
//! cryptographic review is REQUIRED before mainnet.

use crate::errors::CryptoError;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// A ring member: its one-time spend public key and its output commitment.
#[derive(Clone, Copy)]
pub struct RingMember {
    pub public_key: RistrettoPoint, // P_i
    pub commitment: RistrettoPoint, // C_i
}

/// A dual-key CLSAG signature.
pub struct DualCLSAGSignature {
    pub c0: Scalar,
    pub s: Vec<Scalar>,                 // one response per ring member
    pub key_image: CompressedRistretto, // I = p · H_p(P_π)
    pub d: CompressedRistretto,         // D = z · H_p(P_π)
}

/// Hash-to-point: map a public key to a curve point (for key images).
fn hash_to_point(pubkey: &RistrettoPoint) -> RistrettoPoint {
    let h = Sha512::digest(pubkey.compress().as_bytes());
    RistrettoPoint::from_uniform_bytes(&h.into())
}

/// Spend key image: I = p · H_p(P).
pub fn key_image(spend_secret: &Scalar, public_key: &RistrettoPoint) -> RistrettoPoint {
    spend_secret * hash_to_point(public_key)
}

/// Feed the ring + pseudo-output into a hasher (canonical: count || P_i || C_i || C').
fn feed_ring(h: &mut Sha512, ring: &[RingMember], pseudo_out: &RistrettoPoint) {
    h.update((ring.len() as u32).to_le_bytes());
    for m in ring {
        h.update(m.public_key.compress().as_bytes());
        h.update(m.commitment.compress().as_bytes());
    }
    h.update(pseudo_out.compress().as_bytes());
}

/// Aggregation coefficient (domain-separated): binds the full ring + both images.
fn agg_coeff(
    domain: &[u8],
    ring: &[RingMember],
    pseudo_out: &RistrettoPoint,
    i_img: &RistrettoPoint,
    d_img: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(domain);
    feed_ring(&mut h, ring, pseudo_out);
    h.update(i_img.compress().as_bytes());
    h.update(d_img.compress().as_bytes());
    Scalar::from_hash(h)
}

/// Challenge hash: binds message + ring + pseudo-output + (L, R).
fn challenge(
    message: &[u8],
    ring: &[RingMember],
    pseudo_out: &RistrettoPoint,
    l_point: &RistrettoPoint,
    r_point: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"CLSAG2_chal_v1");
    h.update((message.len() as u32).to_le_bytes());
    h.update(message);
    feed_ring(&mut h, ring, pseudo_out);
    h.update(l_point.compress().as_bytes());
    h.update(r_point.compress().as_bytes());
    Scalar::from_hash(h)
}

/// Create a dual-key CLSAG signature.
///
/// `commitment_secret` (= z) must satisfy `ring[secret_index].commitment -
/// pseudo_out == z·G`. `spend_secret` (= p) must satisfy
/// `ring[secret_index].public_key == p·G`.
pub fn sign(
    message: &[u8],
    ring: &[RingMember],
    pseudo_out: &RistrettoPoint,
    secret_index: usize,
    spend_secret: &Scalar,
    commitment_secret: &Scalar,
) -> Result<DualCLSAGSignature, CryptoError> {
    use rand::rngs::OsRng;
    use zeroize::Zeroize;

    let n = ring.len();
    if secret_index >= n {
        return Err(CryptoError::InvalidRingIndex {
            index: secret_index,
            ring_size: n,
        });
    }
    let g = RISTRETTO_BASEPOINT_POINT;
    let hp_pi = hash_to_point(&ring[secret_index].public_key);
    let i_img = spend_secret * hp_pi;
    let d_img = commitment_secret * hp_pi;

    let mu_p = agg_coeff(b"CLSAG2_agg_P_v1", ring, pseudo_out, &i_img, &d_img);
    let mu_c = agg_coeff(b"CLSAG2_agg_C_v1", ring, pseudo_out, &i_img, &d_img);

    // Aggregated signer secret and aggregated key image.
    let mut w = mu_p * spend_secret + mu_c * commitment_secret;
    let w_image = mu_p * i_img + mu_c * d_img;

    let mut alpha = Scalar::random(&mut OsRng);
    let mut c = vec![Scalar::ZERO; n];
    let mut s = vec![Scalar::ZERO; n];
    for item in s.iter_mut() {
        *item = Scalar::random(&mut OsRng);
    }

    // Seed challenge at the position after the signer.
    let l0 = alpha * g;
    let r0 = alpha * hp_pi;
    c[(secret_index + 1) % n] = challenge(message, ring, pseudo_out, &l0, &r0);

    // Constant count of n-1 steps regardless of secret_index (timing-safe).
    for step in 0..(n - 1) {
        let idx = (secret_index + 1 + step) % n;
        let next = (idx + 1) % n;
        let hp_i = hash_to_point(&ring[idx].public_key);
        let w_i = mu_p * ring[idx].public_key + mu_c * (ring[idx].commitment - pseudo_out);
        let l_i = s[idx] * g + c[idx] * w_i;
        let r_i = s[idx] * hp_i + c[idx] * w_image;
        c[next] = challenge(message, ring, pseudo_out, &l_i, &r_i);
    }

    // Close the ring.
    s[secret_index] = alpha - c[secret_index] * w;

    let sig = DualCLSAGSignature {
        c0: c[0],
        s,
        key_image: i_img.compress(),
        d: d_img.compress(),
    };
    alpha.zeroize();
    w.zeroize();
    Ok(sig)
}

/// Verify a dual-key CLSAG signature. Returns true iff the ring closes.
#[allow(clippy::needless_range_loop)]
pub fn verify(
    message: &[u8],
    ring: &[RingMember],
    pseudo_out: &RistrettoPoint,
    sig: &DualCLSAGSignature,
) -> bool {
    let n = ring.len();
    if n == 0 || sig.s.len() != n {
        return false;
    }
    let g = RISTRETTO_BASEPOINT_POINT;
    let i_img = match sig.key_image.decompress() {
        Some(p) => p,
        None => return false,
    };
    let d_img = match sig.d.decompress() {
        Some(p) => p,
        None => return false,
    };
    let mu_p = agg_coeff(b"CLSAG2_agg_P_v1", ring, pseudo_out, &i_img, &d_img);
    let mu_c = agg_coeff(b"CLSAG2_agg_C_v1", ring, pseudo_out, &i_img, &d_img);
    let w_image = mu_p * i_img + mu_c * d_img;

    let mut c = sig.c0;
    for i in 0..n {
        let hp_i = hash_to_point(&ring[i].public_key);
        let w_i = mu_p * ring[i].public_key + mu_c * (ring[i].commitment - pseudo_out);
        let l_i = sig.s[i] * g + c * w_i;
        let r_i = sig.s[i] * hp_i + c * w_image;
        c = challenge(message, ring, pseudo_out, &l_i, &r_i);
    }
    c == sig.c0
}

/// Wire format: c0(32) || count(u32 LE) || s_i(32)* || key_image(32) || d(32).
pub fn to_bytes(sig: &DualCLSAGSignature) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 4 + sig.s.len() * 32 + 64);
    out.extend_from_slice(sig.c0.as_bytes());
    out.extend_from_slice(&(sig.s.len() as u32).to_le_bytes());
    for s in &sig.s {
        out.extend_from_slice(s.as_bytes());
    }
    out.extend_from_slice(sig.key_image.as_bytes());
    out.extend_from_slice(sig.d.as_bytes());
    out
}

/// Parse a signature, rejecting non-canonical scalars / undecompressable points.
pub fn from_bytes(b: &[u8]) -> Option<DualCLSAGSignature> {
    if b.len() < 36 {
        return None;
    }
    let c0 = scalar_from(&b[0..32])?;
    let count = u32::from_le_bytes(b[32..36].try_into().ok()?) as usize;
    let need = 36 + count * 32 + 64;
    if b.len() != need {
        return None;
    }
    let mut s = Vec::with_capacity(count);
    for i in 0..count {
        let off = 36 + i * 32;
        s.push(scalar_from(&b[off..off + 32])?);
    }
    let ki_off = 36 + count * 32;
    let mut ki = [0u8; 32];
    ki.copy_from_slice(&b[ki_off..ki_off + 32]);
    let mut dd = [0u8; 32];
    dd.copy_from_slice(&b[ki_off + 32..ki_off + 64]);
    let key_image = CompressedRistretto(ki);
    let d = CompressedRistretto(dd);
    key_image.decompress()?;
    d.decompress()?;
    Some(DualCLSAGSignature {
        c0,
        s,
        key_image,
        d,
    })
}

pub fn to_hex(sig: &DualCLSAGSignature) -> String {
    hex::encode(to_bytes(sig))
}

pub fn from_hex(h: &str) -> Option<DualCLSAGSignature> {
    from_bytes(&hex::decode(h).ok()?)
}

fn scalar_from(b: &[u8]) -> Option<Scalar> {
    let arr: [u8; 32] = b.try_into().ok()?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    #[test]
    fn key_image_is_deterministic_and_linkable() {
        let p = Scalar::random(&mut OsRng);
        let pubk = p * RISTRETTO_BASEPOINT_POINT;
        assert_eq!(key_image(&p, &pubk), key_image(&p, &pubk));
        let p2 = Scalar::random(&mut OsRng);
        let pubk2 = p2 * RISTRETTO_BASEPOINT_POINT;
        assert_ne!(key_image(&p, &pubk), key_image(&p2, &pubk2));
    }

    /// Build a ring of `n` members. The signer at `idx` gets a known
    /// (spend secret, commitment blinding offset z); decoys get random keys
    /// and commitments. `pseudo_out` is set so C_signer - pseudo_out = z·G.
    fn build_case(n: usize, idx: usize) -> (Vec<RingMember>, RistrettoPoint, Scalar, Scalar) {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h_gen = crate::engine::privacy::confidential::pedersen::generator_h();
        let mut ring = Vec::with_capacity(n);
        for _ in 0..n {
            let sk = Scalar::random(&mut OsRng);
            let blind = Scalar::random(&mut OsRng);
            let amount = Scalar::from(7u64);
            ring.push(RingMember {
                public_key: sk * g,
                commitment: amount * h_gen + blind * g,
            });
        }
        let spend = Scalar::random(&mut OsRng);
        let amount = Scalar::from(7u64);
        let r_pi = Scalar::random(&mut OsRng);
        ring[idx].public_key = spend * g;
        ring[idx].commitment = amount * h_gen + r_pi * g;
        let r_prime = Scalar::random(&mut OsRng);
        let pseudo_out = amount * h_gen + r_prime * g;
        let z = r_pi - r_prime; // C_pi - pseudo_out = z·G
        (ring, pseudo_out, spend, z)
    }

    #[test]
    fn sign_verify_roundtrip_various_sizes_and_indices() {
        for n in [1usize, 2, 4, 11] {
            for idx in 0..n {
                let (ring, pseudo, spend, z) = build_case(n, idx);
                let sig = sign(b"msg", &ring, &pseudo, idx, &spend, &z).unwrap();
                assert!(
                    verify(b"msg", &ring, &pseudo, &sig),
                    "roundtrip failed for n={n} idx={idx}"
                );
            }
        }
    }

    #[test]
    fn sign_rejects_out_of_range_index() {
        let (ring, pseudo, spend, z) = build_case(4, 0);
        assert!(sign(b"m", &ring, &pseudo, 9, &spend, &z).is_err());
    }

    #[test]
    fn rejects_wrong_message() {
        let (ring, pseudo, spend, z) = build_case(4, 2);
        let sig = sign(b"correct", &ring, &pseudo, 2, &spend, &z).unwrap();
        assert!(!verify(b"wrong", &ring, &pseudo, &sig));
    }

    #[test]
    fn rejects_tampered_response_and_c0() {
        let (ring, pseudo, spend, z) = build_case(4, 1);
        let base = sign(b"m", &ring, &pseudo, 1, &spend, &z).unwrap();

        let mut a = DualCLSAGSignature {
            c0: base.c0,
            s: base.s.clone(),
            key_image: base.key_image,
            d: base.d,
        };
        a.s[0] += Scalar::ONE;
        assert!(!verify(b"m", &ring, &pseudo, &a));

        let b = DualCLSAGSignature {
            c0: base.c0 + Scalar::ONE,
            s: base.s.clone(),
            key_image: base.key_image,
            d: base.d,
        };
        assert!(!verify(b"m", &ring, &pseudo, &b));
    }

    #[test]
    fn rejects_tampered_key_image_or_d() {
        let (ring, pseudo, spend, z) = build_case(4, 0);
        let base = sign(b"m", &ring, &pseudo, 0, &spend, &z).unwrap();
        let other = (Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT).compress();

        let a = DualCLSAGSignature {
            c0: base.c0,
            s: base.s.clone(),
            key_image: other,
            d: base.d,
        };
        assert!(!verify(b"m", &ring, &pseudo, &a));
        let b = DualCLSAGSignature {
            c0: base.c0,
            s: base.s.clone(),
            key_image: base.key_image,
            d: other,
        };
        assert!(!verify(b"m", &ring, &pseudo, &b));
    }

    #[test]
    fn rejects_wrong_pseudo_out() {
        let (ring, pseudo, spend, z) = build_case(4, 3);
        let sig = sign(b"m", &ring, &pseudo, 3, &spend, &z).unwrap();
        let other = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        assert!(!verify(b"m", &ring, &other, &sig));
    }

    #[test]
    fn rejects_cross_ring() {
        let (ring_a, pseudo, spend, z) = build_case(4, 1);
        let sig = sign(b"m", &ring_a, &pseudo, 1, &spend, &z).unwrap();
        let (mut ring_b, _, _, _) = build_case(4, 1);
        ring_b[1] = ring_a[0];
        assert!(!verify(b"m", &ring_b, &pseudo, &sig));
    }

    #[test]
    fn rejects_tampered_ring_member() {
        let (mut ring, pseudo, spend, z) = build_case(4, 2);
        let sig = sign(b"m", &ring, &pseudo, 2, &spend, &z).unwrap();
        ring[0].commitment += RISTRETTO_BASEPOINT_POINT;
        assert!(!verify(b"m", &ring, &pseudo, &sig));
    }

    #[test]
    fn verifies_only_when_commitment_offset_matches_z() {
        let (ring, pseudo, spend, z) = build_case(5, 2);
        let good = sign(b"m", &ring, &pseudo, 2, &spend, &z).unwrap();
        assert!(verify(b"m", &ring, &pseudo, &good));

        let z_bad = z + Scalar::ONE;
        let bad = sign(b"m", &ring, &pseudo, 2, &spend, &z_bad).unwrap();
        assert!(
            !verify(b"m", &ring, &pseudo, &bad),
            "a commitment secret that doesn't open C_pi - pseudo_out must not verify"
        );
    }

    #[test]
    fn serialization_round_trips() {
        let (ring, pseudo, spend, z) = build_case(4, 1);
        let sig = sign(b"m", &ring, &pseudo, 1, &spend, &z).unwrap();
        let hex = to_hex(&sig);
        let back = from_hex(&hex).expect("decode");
        assert_eq!(sig.c0, back.c0);
        assert_eq!(sig.s, back.s);
        assert_eq!(sig.key_image, back.key_image);
        assert_eq!(sig.d, back.d);
        assert!(verify(b"m", &ring, &pseudo, &back));
    }

    #[test]
    fn serialization_rejects_malformed() {
        assert!(from_hex("deadbeef").is_none());
        assert!(from_hex("zz").is_none());
    }

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn prop_sign_then_verify(
            n in 1usize..8,
            seed in any::<u64>(),
            msg in proptest::collection::vec(any::<u8>(), 0..40),
        ) {
            let idx = (seed as usize) % n;
            let (ring, pseudo, spend, z) = build_case(n, idx);
            let sig = sign(&msg, &ring, &pseudo, idx, &spend, &z).unwrap();
            prop_assert!(verify(&msg, &ring, &pseudo, &sig));
            let mut bad = DualCLSAGSignature {
                c0: sig.c0,
                s: sig.s.clone(),
                key_image: sig.key_image,
                d: sig.d,
            };
            bad.s[0] += Scalar::ONE;
            prop_assert!(!verify(&msg, &ring, &pseudo, &bad));
        }
    }

    #[test]
    fn frozen_kat_serialization_shape() {
        let (ring, pseudo, spend, z) = build_case(11, 5);
        let sig = sign(b"kat", &ring, &pseudo, 5, &spend, &z).unwrap();
        let bytes = to_bytes(&sig);
        assert_eq!(bytes.len(), 32 + 4 + 11 * 32 + 64);
        assert!(verify(b"kat", &ring, &pseudo, &from_bytes(&bytes).unwrap()));
    }
}
