// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Cryptographic precompiles — signature verification, key recovery, commitments.
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

use super::precompile_registry::PrecompileResult;

// ── Gas cost constants ────────────────────────────────────────────────────
const GAS_ECRECOVER: u64 = 3_000;
const GAS_ED25519_VERIFY: u64 = 2_000;
const GAS_PEDERSEN_COMMIT: u64 = 5_000;

/// 0x01: Ed25519 signature verification and address recovery.
///
/// **NOTE:** Despite the legacy name `ecrecover` (retained in the registry for
/// EVM tooling compatibility at address 0x01), this is an **Ed25519 verify +
/// address derivation**, NOT secp256k1 ECDSA recovery. ShadowDAG uses Ed25519
/// as its native signature scheme.
///
/// Input format (128 bytes):
///   [0..32]   message hash
///   [32..64]  public key (32 bytes, Ed25519)
///   [64..128] signature (64 bytes, Ed25519)
///
/// Output: 32-byte address derived from SHA-256(pubkey) (if valid), else 32 zero bytes
pub fn ecrecover(input: &[u8], _gas_limit: u64) -> PrecompileResult {
    let gas_used = GAS_ECRECOVER;

    if input.len() < 128 {
        return PrecompileResult::err("ecrecover: input must be 128 bytes", gas_used);
    }

    let message = &input[0..32];
    let pubkey_bytes = &input[32..64];
    let sig_bytes = &input[64..128];

    // Parse public key
    let pk_array: [u8; 32] = match pubkey_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return PrecompileResult::err("ecrecover: invalid public key", gas_used),
    };

    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(k) => k,
        Err(_) => return PrecompileResult::err("ecrecover: invalid public key point", gas_used),
    };

    // Parse signature
    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return PrecompileResult::err("ecrecover: invalid signature", gas_used),
    };

    let signature = Signature::from_bytes(&sig_array);

    // Verify
    if verifying_key.verify(message, &signature).is_ok() {
        // Derive address: SHA-256(pubkey)[0..32]
        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, pubkey_bytes);
        let hash = Digest::finalize(h);
        PrecompileResult::ok(hash.to_vec(), gas_used)
    } else {
        // Invalid signature — return 32 zero bytes (like Ethereum)
        PrecompileResult::ok(vec![0u8; 32], gas_used)
    }
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

    if vk.verify(message, &sig).is_ok() {
        PrecompileResult::ok(vec![0x01], gas_used)
    } else {
        PrecompileResult::ok(vec![0x00], gas_used)
    }
}

/// 0x09: Hash-based commitment (domain-separated SHA-256).
///
/// **NOTE:** This is a SHA-256 domain-separated hash commitment, NOT a
/// Pedersen commitment on an elliptic curve. The name `pedersen_commit` is
/// retained for registry/ABI compatibility. For actual Pedersen commitments
/// with homomorphic properties, use the privacy layer
/// (`engine/privacy/confidential/pedersen_commitment.rs`).
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
        return PrecompileResult::err("pedersen: input must be 40 bytes (8 value + 32 blinding)", gas_used);
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
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::Signer;

    #[test]
    fn ecrecover_valid_signature() {
        // Generate keypair
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let vk = sk.verifying_key();

        // Sign a message
        let message = [0xABu8; 32];
        let sig = sk.sign(&message);

        // Build input: message(32) + pubkey(32) + sig(64)
        let mut input = Vec::with_capacity(128);
        input.extend_from_slice(&message);
        input.extend_from_slice(vk.as_bytes());
        input.extend_from_slice(&sig.to_bytes());

        let result = ecrecover(&input, 100_000);
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
        // Should be non-zero (recovered address)
        assert!(result.output.iter().any(|&b| b != 0));
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
