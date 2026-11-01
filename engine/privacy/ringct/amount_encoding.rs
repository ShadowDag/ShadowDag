// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! RingCT amount encoding: derive the output blinding and an amount one-time-pad
//! from the ECDH shared secret, so the recipient (who recomputes the same shared
//! secret) recovers both. Domain-separated from the stealth address derivation.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha256, Sha512};

/// Output commitment blinding, derived from the ECDH shared secret + index.
pub fn derive_blinding(shared_secret: &RistrettoPoint, index: u32) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"ShadowDAG_RingCT_commit_mask_v1");
    h.update(shared_secret.compress().as_bytes());
    h.update(index.to_le_bytes());
    Scalar::from_hash(h)
}

/// 8-byte one-time pad for the amount, derived from the shared secret + index.
pub fn amount_mask(shared_secret: &RistrettoPoint, index: u32) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_RingCT_amount_v1");
    h.update(shared_secret.compress().as_bytes());
    h.update(index.to_le_bytes());
    let full: [u8; 32] = h.finalize().into();
    let mut m = [0u8; 8];
    m.copy_from_slice(&full[..8]);
    m
}

/// XOR-encrypt the amount with the mask (one-time pad).
pub fn encrypt_amount(amount: u64, mask: &[u8; 8]) -> [u8; 8] {
    let a = amount.to_le_bytes();
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = a[i] ^ mask[i];
    }
    out
}

/// Decrypt the masked amount.
pub fn decrypt_amount(enc: &[u8; 8], mask: &[u8; 8]) -> u64 {
    let mut a = [0u8; 8];
    for i in 0..8 {
        a[i] = enc[i] ^ mask[i];
    }
    u64::from_le_bytes(a)
}

pub fn enc_to_hex(enc: &[u8; 8]) -> String {
    hex::encode(enc)
}

pub fn enc_from_hex(h: &str) -> Option<[u8; 8]> {
    let bytes = hex::decode(h).ok()?;
    let arr: [u8; 8] = bytes.try_into().ok()?;
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use rand::rngs::OsRng;

    fn ss() -> RistrettoPoint {
        Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let s = ss();
        for amt in [0u64, 1, 42, u64::MAX] {
            let mask = amount_mask(&s, 0);
            let enc = encrypt_amount(amt, &mask);
            assert_eq!(decrypt_amount(&enc, &mask), amt);
        }
    }

    #[test]
    fn mask_and_blinding_depend_on_ss_and_index() {
        let a = ss();
        let b = ss();
        assert_ne!(amount_mask(&a, 0), amount_mask(&b, 0));
        assert_ne!(amount_mask(&a, 0), amount_mask(&a, 1));
        assert_ne!(derive_blinding(&a, 0), derive_blinding(&b, 0));
        assert_ne!(derive_blinding(&a, 0), derive_blinding(&a, 1));
        assert_eq!(derive_blinding(&a, 3), derive_blinding(&a, 3));
    }

    #[test]
    fn hex_round_trips() {
        let mask = amount_mask(&ss(), 2);
        let enc = encrypt_amount(7, &mask);
        let h = enc_to_hex(&enc);
        assert_eq!(enc_from_hex(&h), Some(enc));
        assert!(enc_from_hex("zz").is_none());
        assert!(enc_from_hex("00").is_none());
    }
}
