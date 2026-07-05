// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Cryptographic precompiles — signature verification, key recovery, commitments.
// ═══════════════════════════════════════════════════════════════════════════

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use super::precompile_registry::PrecompileResult;

// ── Gas cost constants ────────────────────────────────────────────────────
const GAS_ECRECOVER: u64 = 3_000;
const GAS_ED25519_VERIFY: u64 = 2_000;
const GAS_PEDERSEN_COMMIT: u64 = 5_000;

/// 0x01: ecrecover — standard Ethereum secp256k1 ECDSA public-key recovery.
///
/// Input (128 bytes, right-padded if short): hash[0..32] || v[32..64] ||
/// r[64..96] || s[96..128], where v is 27 or 28 (big-endian in the last byte).
/// Output: 32 bytes = 12 zero bytes || 20-byte Ethereum address
/// (keccak256(uncompressed_pubkey[1..65])[12..32]). Any invalid input, v, or
/// signature yields the 32-byte zero address, matching the EVM precompile.
pub fn ecrecover(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    use k256::ecdsa::{RecoveryId, Signature as Secp256k1Sig, VerifyingKey as Secp256k1Vk};
    use sha3::{Digest as Sha3Digest, Keccak256};

    let gas_used = GAS_ECRECOVER;
    let zero = || PrecompileResult::ok(vec![0u8; 32], gas_used);

    let mut buf = [0u8; 128];
    let n = input.len().min(128);
    buf[..n].copy_from_slice(&input[..n]);

    let hash = &buf[0..32];
    // v is a 32-byte big-endian value that must be exactly 27 or 28.
    if buf[32..63].iter().any(|&b| b != 0) {
        return zero();
    }
    let recovery_id = match buf[63] {
        27 => RecoveryId::from_byte(0),
        28 => RecoveryId::from_byte(1),
        _ => return zero(),
    };
    let recovery_id = match recovery_id {
        Some(r) => r,
        None => return zero(),
    };
    let signature = match Secp256k1Sig::from_slice(&buf[64..128]) {
        Ok(s) => s,
        Err(_) => return zero(),
    };
    let vk = match Secp256k1Vk::recover_from_prehash(hash, &signature, recovery_id) {
        Ok(k) => k,
        Err(_) => return zero(),
    };

    let encoded = vk.to_encoded_point(false);
    let pubkey = &encoded.as_bytes()[1..]; // strip 0x04 prefix -> 64 bytes (X||Y)
    let mut kh = Keccak256::new();
    Sha3Digest::update(&mut kh, pubkey);
    let digest = kh.finalize();
    let mut out = vec![0u8; 32];
    out[12..32].copy_from_slice(&digest[12..32]);
    PrecompileResult::ok(out, gas_used)
}

/// 0x08: ED25519_VERIFY — verify Ed25519 signature (return 1 or 0)
///
/// Input format (128 bytes):
///   [0..32]   message hash
///   [32..64]  public key
///   [64..128] signature
///
/// Output: 1 byte (0x01 = valid, 0x00 = invalid)
pub fn ed25519_verify(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    let gas_used = GAS_ED25519_VERIFY;

    if input.len() < 128 {
        return PrecompileResult::ok(vec![0x00], gas_used);
    }

    let message = &input[0..32];
    let pubkey_bytes: [u8; 32] = match input[32..64].try_into() {
        Ok(a) => a,
        Err(_) => return PrecompileResult::ok(vec![0x00], gas_used),
    };
    let sig_bytes: [u8; 64] = match input[64..128].try_into() {
        Ok(a) => a,
        Err(_) => return PrecompileResult::ok(vec![0x00], gas_used),
    };

    let vk = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(_) => return PrecompileResult::ok(vec![0x00], gas_used),
    };

    let sig = Signature::from_bytes(&sig_bytes);

    // verify_strict rejects malleable/non-canonical signatures (torsion / small-
    // order points), matching the tx path (TxValidator uses verify_strict). Plain
    // verify() let a contract-reachable 0x08 accept a second valid signature for
    // one (key, message), defeating replay/uniqueness assumptions (B5-M02).
    if vk.verify_strict(message, &sig).is_ok() {
        PrecompileResult::ok(vec![0x01], gas_used)
    } else {
        PrecompileResult::ok(vec![0x00], gas_used)
    }
}

/// 0x09: SHA-256 based commitment (domain-separated).
///
/// **WARNING: This is NOT a real Pedersen commitment.** A true Pedersen
/// commitment uses elliptic curve points (C = v*G + r*H) and has homomorphic
/// properties (commitments can be added: C1 + C2 commits to v1 + v2). This
/// implementation is a plain SHA-256 hash and has NONE of those properties.
/// Contracts relying on homomorphic addition of commitments will silently
/// produce incorrect results.
///
/// The function name `pedersen_commit` is retained for registry/ABI
/// compatibility at address 0x09. For actual Pedersen commitments with
/// homomorphic properties, use the privacy layer
/// (`engine/privacy/confidential/pedersen.rs`, `RealPedersenCommitment`).
///
/// Input format (40 bytes):
///   [0..8]   value (u64 LE)
///   [8..40]  blinding factor (32 bytes)
///
/// Output: 32-byte commitment hash
///
/// Commitment = SHA-256("PEDERSEN_SHADOW_V1" || value || blinding_factor)
pub fn pedersen_commit(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    let gas_used = GAS_PEDERSEN_COMMIT;

    if input.len() < 40 {
        return PrecompileResult::err(
            "pedersen: input must be 40 bytes (8 value + 32 blinding)",
            gas_used,
        );
    }

    let value_bytes = &input[0..8];
    let blinding = &input[8..40];

    // Commitment: H(domain || value || blinding)
    let mut h = <Sha256 as Digest>::new();
    Digest::update(&mut h, b"PEDERSEN_SHADOW_V1");
    Digest::update(&mut h, value_bytes);
    Digest::update(&mut h, blinding);
    let commitment = Digest::finalize(h);

    PrecompileResult::ok(commitment.to_vec(), gas_used)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;

    #[test]
    fn ecrecover_recovers_signer_address() {
        use k256::ecdsa::{RecoveryId, Signature as K256Sig, SigningKey};
        use sha3::{Digest as Sha3Digest, Keccak256};

        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let vk = sk.verifying_key();
        // Expected Ethereum address = keccak256(uncompressed_pubkey[1..])[12..].
        let enc = vk.to_encoded_point(false);
        let mut kh = Keccak256::new();
        Sha3Digest::update(&mut kh, &enc.as_bytes()[1..]);
        let d = kh.finalize();
        let mut expected = vec![0u8; 32];
        expected[12..32].copy_from_slice(&d[12..32]);

        let hash = [0x11u8; 32];
        let (sig, recid): (K256Sig, RecoveryId) = sk.sign_prehash_recoverable(&hash).unwrap();
        let mut input = vec![0u8; 128];
        input[0..32].copy_from_slice(&hash);
        input[63] = 27 + recid.to_byte();
        input[64..128].copy_from_slice(&sig.to_bytes());

        let result = ecrecover(&input, 100_000);
        assert!(result.success);
        assert_eq!(result.output, expected, "recovered address must match the signer");
    }

    #[test]
    fn ecrecover_invalid_signature() {
        let mut input = vec![0u8; 128];
        input[32] = 1; // Need a non-zero pubkey
                       // This will fail since the signature is invalid
        let result = ecrecover(&input, 100_000);
        // Either error or zero output
        assert!(!result.success || result.output == vec![0u8; 32]);
    }

    #[test]
    fn ed25519_verify_valid() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let message = [0x42u8; 32];
        let sig = sk.sign(&message);

        let mut input = Vec::with_capacity(128);
        input.extend_from_slice(&message);
        input.extend_from_slice(vk.as_bytes());
        input.extend_from_slice(&sig.to_bytes());

        let result = ed25519_verify(&input, 100_000);
        assert!(result.success);
        assert_eq!(result.output, vec![0x01]);
    }

    #[test]
    fn ed25519_verify_invalid() {
        let input = vec![0u8; 128];
        let result = ed25519_verify(&input, 100_000);
        assert!(result.success);
        assert_eq!(result.output, vec![0x00]);
    }

    #[test]
    fn pedersen_commit_deterministic() {
        let mut input = vec![0u8; 40];
        input[0..8].copy_from_slice(&100u64.to_le_bytes());
        input[8..40].copy_from_slice(&[0xAA; 32]);

        let r1 = pedersen_commit(&input, 100_000);
        let r2 = pedersen_commit(&input, 100_000);
        assert!(r1.success);
        assert_eq!(r1.output, r2.output);
        assert_eq!(r1.output.len(), 32);
    }

    #[test]
    fn pedersen_different_values_different_commits() {
        let mut input1 = vec![0u8; 40];
        input1[0..8].copy_from_slice(&100u64.to_le_bytes());
        input1[8..40].copy_from_slice(&[0xAA; 32]);

        let mut input2 = vec![0u8; 40];
        input2[0..8].copy_from_slice(&200u64.to_le_bytes());
        input2[8..40].copy_from_slice(&[0xAA; 32]);

        let r1 = pedersen_commit(&input1, 100_000);
        let r2 = pedersen_commit(&input2, 100_000);
        assert_ne!(r1.output, r2.output);
    }
}
