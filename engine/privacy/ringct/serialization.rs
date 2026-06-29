// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Byte/hex (de)serialization for CLSAG signatures and Ristretto points.
//!
//! The curve types in `clsag.rs` are not serde-serializable, so transactions
//! carry the CLSAG signature as a hex string. Every parser validates canonical
//! encoding: scalars must be canonical, points must decompress.

use crate::engine::privacy::ringct::clsag::CLSAGSignature;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

/// Wire format: `c0(32) || count(u32 LE) || s_i(32)* || key_image(32)`.
pub fn clsag_sig_to_bytes(sig: &CLSAGSignature) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 4 + sig.s.len() * 32 + 32);
    out.extend_from_slice(sig.c0.as_bytes());
    out.extend_from_slice(&(sig.s.len() as u32).to_le_bytes());
    for s in &sig.s {
        out.extend_from_slice(s.as_bytes());
    }
    out.extend_from_slice(sig.key_image.as_bytes());
    out
}

/// Parse a CLSAG signature, requiring canonical scalars and a decompressible
/// key image. Returns `None` on any malformed/truncated input.
pub fn clsag_sig_from_bytes(b: &[u8]) -> Option<CLSAGSignature> {
    if b.len() < 36 {
        return None;
    }
    let c0 = scalar_from(&b[0..32])?;
    let count = u32::from_le_bytes(b[32..36].try_into().ok()?) as usize;
    let need = 36 + count * 32 + 32;
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
    let key_image = CompressedRistretto(ki);
    // Must decompress to a valid point.
    key_image.decompress()?;
    Some(CLSAGSignature { c0, s, key_image })
}

pub fn clsag_sig_to_hex(sig: &CLSAGSignature) -> String {
    hex::encode(clsag_sig_to_bytes(sig))
}

pub fn clsag_sig_from_hex(h: &str) -> Option<CLSAGSignature> {
    clsag_sig_from_bytes(&hex::decode(h).ok()?)
}

/// Parse a hex compressed-Ristretto point, requiring it to decompress.
pub fn point_from_hex(h: &str) -> Option<RistrettoPoint> {
    let bytes = hex::decode(h).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    CompressedRistretto(arr).decompress()
}

fn scalar_from(b: &[u8]) -> Option<Scalar> {
    let arr: [u8; 32] = b.try_into().ok()?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::privacy::ringct::clsag;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand::rngs::OsRng;

    fn sample_sig() -> clsag::CLSAGSignature {
        let pairs: Vec<(Scalar, RistrettoPoint)> = (0..4)
            .map(|_| {
                let sk = Scalar::random(&mut OsRng);
                (sk, sk * RISTRETTO_BASEPOINT_POINT)
            })
            .collect();
        let ring: Vec<_> = pairs.iter().map(|(_, pk)| *pk).collect();
        clsag::sign(b"msg", &ring, 1, &pairs[1].0).unwrap()
    }

    #[test]
    fn clsag_hex_round_trips() {
        let sig = sample_sig();
        let hex = clsag_sig_to_hex(&sig);
        let back = clsag_sig_from_hex(&hex).unwrap();
        assert_eq!(sig.c0, back.c0);
        assert_eq!(sig.s, back.s);
        assert_eq!(sig.key_image, back.key_image);
    }

    #[test]
    fn rejects_truncated() {
        assert!(clsag_sig_from_hex("deadbeef").is_none());
    }

    #[test]
    fn rejects_non_hex() {
        assert!(clsag_sig_from_hex("zzzz").is_none());
    }

    #[test]
    fn point_from_hex_round_trips() {
        let p = RISTRETTO_BASEPOINT_POINT;
        let h = hex::encode(p.compress().as_bytes());
        assert_eq!(point_from_hex(&h), Some(p));
        assert!(point_from_hex("00").is_none());
    }
}
