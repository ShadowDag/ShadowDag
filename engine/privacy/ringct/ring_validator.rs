// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::transaction::transaction::Transaction;
#[allow(deprecated)]
use crate::engine::privacy::ringct::ring_signature::RingSignature;

/// Validates ring signature aspects of a transaction.
///
/// # Privacy wiring status
///
/// **Current state (legacy):** Uses `RingSignature::verify()` which only
/// performs structural checks (key_image format, ring_members presence/size).
/// This does NOT verify actual cryptographic ring signatures.
///
/// **Target state:** Should use `crate::engine::privacy::ringct::clsag::verify()`
/// which implements real CLSAG (Compact Linkable Spontaneous Anonymous Group)
/// ring signatures using curve25519-dalek Ristretto points.
///
/// **Migration path:**
///   1. `TxInput` must carry serialized `CLSAGSignature` data (c0, s[], key_image
///      as compressed Ristretto points) instead of bare hex strings
///   2. `ring_members` must be deserialized into `Vec<RistrettoPoint>`
///   3. Each input's CLSAG signature is verified via `clsag::verify(message, ring, sig)`
///   4. Once wired, `RingSignature::verify()` can be removed entirely
pub struct RingValidator;

impl RingValidator {
    #[allow(deprecated)]
    pub fn validate(tx: &Transaction) -> bool {
        // 1. Ring signature structural checks (LEGACY)
        //
        // WARNING: RingSignature::verify() is DEPRECATED — it only checks that
        // key_image and ring_members fields are present and well-formed. It does
        // NOT perform cryptographic ring signature verification.
        //
        // TODO(privacy): Wire CLSAG verification here. Requires:
        //   - Deserialize each input's signature bytes into clsag::CLSAGSignature
        //   - Deserialize ring_members from hex strings into RistrettoPoints
        //   - Call clsag::verify(tx_message, &ring_points, &clsag_sig) per input
        //   - See engine/privacy/ringct/clsag.rs for the real implementation
        //
        // The CLSAG module (clsag.rs) is fully implemented and tested. The gap is
        // that Transaction/TxInput currently stores ring data as hex strings, not
        // as the typed crypto structures that clsag::verify() expects.
        #[allow(deprecated)]
        let structural_ok = RingSignature::verify(tx);
        if !structural_ok {
            return false;
        }

        // NOTE: This function performs STRUCTURAL checks only. Cryptographic
        // CLSAG verification lives in `verify_clsag()`, and the full
        // consensus gate (crypto + on-chain ring-member authenticity +
        // key-image uniqueness) lives in `TxValidator::validate_confidential()`,
        // which has UTXO-set access. Callers validating confidential TXs for
        // consensus MUST use `validate_confidential`, not `validate` alone.

        // 2. Non-empty outputs
        if tx.outputs.is_empty() {
            return false;
        }
        // 3. Key image validation
        let key_images = RingSignature::key_images(tx);
        if key_images.is_empty() && !tx.inputs.is_empty() {
            return false;
        }
        // Defense-in-depth: each input must have exactly one key image.
        // tx_validation/mod.rs checks this too, but ring_validator is called
        // from separate code paths (e.g. direct RingCT validation).
        if !key_images.is_empty() && key_images.len() != tx.inputs.len() {
            return false; // Each input must have exactly one key image
        }
        // 4. Key image format check (64 hex chars = 32 bytes compressed Ristretto)
        for ki in &key_images {
            if ki.len() != 64 || !ki.chars().all(|c| c.is_ascii_hexdigit()) {
                return false;
            }
        }
        // 5. Key image UNIQUENESS within this transaction
        // Duplicate key images = double-spend attempt within the same TX
        {
            let mut seen = std::collections::HashSet::with_capacity(key_images.len());
            for ki in &key_images {
                if !seen.insert(ki.as_str()) {
                    return false; // Duplicate key image
                }
            }
        }
        // 6. Ring size validation (minimum mixin for privacy)
        // Each input must have ring_members with at least MIN_RING_SIZE entries.
        // For confidential TXs, ring_members MUST be present (not None).
        const MIN_RING_SIZE: usize = 4; // Minimum 4 decoys for meaningful privacy
        const MAX_RING_SIZE: usize = 64; // Cap to prevent DoS
        for input in &tx.inputs {
            if tx.tx_type == crate::domain::transaction::transaction::TxType::Confidential {
                match &input.ring_members {
                    Some(members)
                        if members.len() >= MIN_RING_SIZE && members.len() <= MAX_RING_SIZE => {}
                    Some(_members) => return false, // Wrong size
                    None => return false,           // Missing for confidential TX
                }
            } else if let Some(ref members) = input.ring_members {
                // Non-confidential with ring_members -- still validate size
                if members.len() < MIN_RING_SIZE || members.len() > MAX_RING_SIZE {
                    return false;
                }
            }
        }

        // Structural checks passed. Cryptographic verification (CLSAG) and the
        // DB-backed gate (ring-member authenticity + key-image uniqueness) are
        // applied by TxValidator::validate_confidential().
        true
    }

    /// Cryptographic CLSAG verification for every confidential input.
    ///
    /// Deserializes each input's `ring_members` (hex compressed Ristretto) and
    /// `ring_signature` (hex CLSAG), then checks the ring closes over the
    /// canonical confidential message. Also requires the input's `key_image`
    /// field to equal the signature's key image. Pure crypto — NO DB access.
    pub fn verify_clsag(
        tx: &Transaction,
        network: &crate::config::node::node_config::NetworkMode,
    ) -> bool {
        use crate::domain::transaction::tx_hash::TxHash;
        use crate::engine::privacy::ringct::clsag;
        use crate::engine::privacy::ringct::serialization::{clsag_sig_from_hex, point_from_hex};

        let msg = TxHash::confidential_signing_message_for_network(tx, network);
        for input in &tx.inputs {
            let members = match &input.ring_members {
                Some(m) if !m.is_empty() => m,
                _ => return false,
            };
            let mut ring = Vec::with_capacity(members.len());
            for m in members {
                match point_from_hex(m) {
                    Some(p) => ring.push(p),
                    None => return false,
                }
            }
            let sig = match &input.ring_signature {
                Some(rs) => match clsag_sig_from_hex(rs) {
                    Some(s) => s,
                    None => return false,
                },
                None => return false,
            };
            // The advertised key image must match the signature's key image.
            match &input.key_image {
                Some(ki) if *ki == hex::encode(sig.key_image.as_bytes()) => {}
                _ => return false,
            }
            if !clsag::verify(&msg, &ring, &sig) {
                return false;
            }
        }
        true
    }

    #[deprecated(
        since = "1.0.0",
        note = "Use validate() instead. quick_validate skips ring signature verification!"
    )]
    pub fn quick_validate(tx: &Transaction) -> bool {
        Self::validate(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};

    /// Helper: valid 64-char hex key image
    fn hex_key_image(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    /// Helper: minimum valid ring members (4 decoys)
    fn min_ring_members() -> Vec<String> {
        (0..4).map(|i| format!("decoy_{}", i)).collect()
    }

    /// Construct a confidential TX with N inputs, each having a key image and ring members.
    fn make_confidential_tx(num_inputs: usize) -> Transaction {
        let inputs: Vec<TxInput> = (0..num_inputs)
            .map(|i| {
                TxInput::new_confidential(
                    format!("prev_{}", i),
                    i as u32,
                    "owner".into(),
                    "sig".into(),
                    "pk".into(),
                    hex_key_image(i as u8 + 1),
                    min_ring_members(),
                )
            })
            .collect();

        Transaction {
            hash: "test_confidential_tx".to_string(),
            inputs,
            outputs: vec![TxOutput::new("recipient".into(), 1000)],
            fee: 100,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Confidential,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn rejects_mismatched_key_images_count() {
        // Regression: TX with 3 inputs but only 1 key image must be rejected.
        // Before the fix, ring_validator only checked if key_images was empty,
        // allowing a TX with fewer key images than inputs to pass.
        let mut tx = make_confidential_tx(3);

        // Remove key images from inputs 1 and 2 so key_images() returns only 1
        tx.inputs[1].key_image = None;
        tx.inputs[2].key_image = None;

        // RingSignature::verify requires key_image on all Confidential inputs,
        // so we need to also make verify() pass by setting tx_type to Transfer
        // while keeping the key_image count mismatch.
        // Actually, since RingSignature::verify checks each input for
        // Confidential tx_type and requires key_image, this TX will already
        // fail at step 1. To specifically test the count check at step 3,
        // use Transfer type with mixed key_image presence:
        tx.tx_type = TxType::Transfer;

        assert!(
            !RingValidator::validate(&tx),
            "TX with 3 inputs but only 1 key image must be rejected"
        );
    }

    #[test]
    fn structural_validate_accepts_matching_key_images_count() {
        // 3 inputs, 3 key images -- structural validate() passes (crypto is
        // checked separately by verify_clsag / validate_confidential).
        let tx = make_confidential_tx(3);
        assert!(
            RingValidator::validate(&tx),
            "TX with matching input/key_image counts should pass structural checks"
        );
    }

    #[test]
    fn structural_validate_rejects_garbage_ring_signature_via_crypto() {
        use crate::config::node::node_config::NetworkMode;
        // Structural validate() passes, but verify_clsag() rejects because the
        // ring_signature is not a valid CLSAG over the message.
        let mut tx = make_confidential_tx(1);
        tx.inputs[0].ring_signature = Some("00".repeat(200));
        assert!(RingValidator::validate(&tx));
        assert!(!RingValidator::verify_clsag(&tx, &NetworkMode::Mainnet));
    }

    #[test]
    fn verify_clsag_accepts_valid_and_rejects_tamper() {
        use crate::config::node::node_config::NetworkMode;
        use crate::domain::transaction::tx_hash::TxHash;
        use crate::engine::privacy::ringct::clsag;
        use crate::engine::privacy::ringct::serialization::clsag_sig_to_hex;
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::scalar::Scalar;
        use rand::rngs::OsRng;

        // Ring of 4 real keypairs; the real signer is index 2.
        let pairs: Vec<(Scalar, _)> = (0..4)
            .map(|_| {
                let sk = Scalar::random(&mut OsRng);
                (sk, sk * RISTRETTO_BASEPOINT_POINT)
            })
            .collect();
        let ring_hex: Vec<String> = pairs
            .iter()
            .map(|(_, pk)| hex::encode(pk.compress().as_bytes()))
            .collect();

        let mut tx = make_confidential_tx(1);
        tx.inputs[0].ring_members = Some(ring_hex);
        let net = NetworkMode::Mainnet;
        // Key image is deterministic from the signer's key — set it BEFORE
        // computing the message (the message binds the key image).
        let ki = clsag::key_image(&pairs[2].0, &pairs[2].1);
        tx.inputs[0].key_image = Some(hex::encode(ki.compress().as_bytes()));
        let msg = TxHash::confidential_signing_message_for_network(&tx, &net);
        let ring: Vec<_> = pairs.iter().map(|(_, p)| *p).collect();
        let sig = clsag::sign(&msg, &ring, 2, &pairs[2].0).unwrap();
        tx.inputs[0].ring_signature = Some(clsag_sig_to_hex(&sig));

        assert!(RingValidator::verify_clsag(&tx, &net), "valid CLSAG must pass");

        // Tamper: replace the signature with garbage of the same shape.
        let mut bad = tx.clone();
        bad.inputs[0].ring_signature = Some(clsag_sig_to_hex(
            &clsag::sign(b"different message", &ring, 2, &pairs[2].0).unwrap(),
        ));
        assert!(
            !RingValidator::verify_clsag(&bad, &net),
            "signature over a different message must fail"
        );
    }
}
