// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! SLIP-0010 hierarchical key derivation for Ed25519 (hardened-only).
//!
//! Ed25519 SLIP-0010 supports hardened derivation only (there is no
//! public-parent → public-child step), which is exactly what a seed-holding
//! wallet needs.
//! Spec: https://github.com/satoshilabs/slips/blob/master/slip-0010.md

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

/// A SLIP-0010 derived node: 32-byte key material + 32-byte chain code.
pub struct Slip10Node {
    pub key: [u8; 32],
    pub chain_code: [u8; 32],
}

impl Drop for Slip10Node {
    fn drop(&mut self) {
        self.key.zeroize();
        self.chain_code.zeroize();
    }
}

impl Slip10Node {
    /// Master node: `I = HMAC-SHA512(key="ed25519 seed", data=seed)`.
    pub fn master_ed25519(seed: &[u8]) -> Self {
        let mut mac =
            HmacSha512::new_from_slice(b"ed25519 seed").expect("HMAC accepts any key length");
        mac.update(seed);
        let i = mac.finalize().into_bytes();
        Self::split(&i)
    }

    /// Hardened child derivation (the only mode valid for ed25519).
    /// `data = 0x00 || key || ser32(index | 0x80000000)`
    pub fn derive_hardened(&self, index: u32) -> Self {
        let hardened = index | 0x8000_0000;
        let mut mac =
            HmacSha512::new_from_slice(&self.chain_code).expect("HMAC accepts any key length");
        mac.update(&[0x00]);
        mac.update(&self.key);
        mac.update(&hardened.to_be_bytes());
        let i = mac.finalize().into_bytes();
        Self::split(&i)
    }

    /// Derive `m/idx0'/idx1'/...` (all elements hardened) from a seed.
    pub fn derive_path_ed25519(seed: &[u8], hardened_path: &[u32]) -> Self {
        let mut node = Self::master_ed25519(seed);
        for &idx in hardened_path {
            node = node.derive_hardened(idx);
        }
        node
    }

    fn split(i: &[u8]) -> Self {
        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&i[0..32]);
        chain_code.copy_from_slice(&i[32..64]);
        Self { key, chain_code }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SLIP-0010 Test vector 1 for ed25519, seed = 000102030405060708090a0b0c0d0e0f
    fn seed() -> Vec<u8> {
        hex::decode("000102030405060708090a0b0c0d0e0f").unwrap()
    }

    #[test]
    fn master_key_matches_vector() {
        let node = Slip10Node::master_ed25519(&seed());
        assert_eq!(
            hex::encode(node.key),
            "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
        );
        assert_eq!(
            hex::encode(node.chain_code),
            "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"
        );
    }

    #[test]
    fn child_m_0h_matches_vector() {
        // m/0'
        let node = Slip10Node::master_ed25519(&seed()).derive_hardened(0);
        assert_eq!(
            hex::encode(node.key),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
        );
        assert_eq!(
            hex::encode(node.chain_code),
            "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"
        );
    }

    #[test]
    fn derive_path_chains_hardened_steps() {
        // m/0'/1' derived two ways must match
        let a = Slip10Node::master_ed25519(&seed())
            .derive_hardened(0)
            .derive_hardened(1);
        let b = Slip10Node::derive_path_ed25519(&seed(), &[0, 1]);
        assert_eq!(a.key, b.key);
        assert_eq!(a.chain_code, b.chain_code);
    }
}
