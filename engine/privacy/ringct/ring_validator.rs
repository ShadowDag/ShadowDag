// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::transaction::transaction::Transaction;
use crate::engine::privacy::ringct::ring_signature::RingSignature;

pub struct RingValidator;

impl RingValidator {
    pub fn validate(tx: &Transaction) -> bool {
        // 1. Ring signature verification
        // TODO: Migrate to CLSAG verification (clsag.rs) for production privacy.
        // Current RingSignature::verify is LEGACY/DEPRECATED in ring_signature.rs.
        // The real CLSAG implementation lives in: engine/privacy/ringct/clsag.rs
        // and uses curve25519-dalek Ristretto points with real elliptic curve math.
        if !RingSignature::verify(tx) {
            return false;
        }
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
        const MIN_RING_SIZE: usize = 4;  // Minimum 4 decoys for meaningful privacy
        const MAX_RING_SIZE: usize = 64; // Cap to prevent DoS
        for input in &tx.inputs {
            if tx.tx_type == crate::domain::transaction::transaction::TxType::Confidential {
                match &input.ring_members {
                    Some(members) if members.len() >= MIN_RING_SIZE && members.len() <= MAX_RING_SIZE => {}
                    Some(_members) => return false, // Wrong size
                    None => return false, // Missing for confidential TX
                }
            } else if let Some(ref members) = input.ring_members {
                // Non-confidential with ring_members -- still validate size
                if members.len() < MIN_RING_SIZE || members.len() > MAX_RING_SIZE {
                    return false;
                }
            }
        }

        true
    }

    #[deprecated(since = "1.0.0", note = "Use validate() instead. quick_validate skips ring signature verification!")]
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
        let inputs: Vec<TxInput> = (0..num_inputs).map(|i| {
            TxInput::new_confidential(
                format!("prev_{}", i), i as u32,
                "owner".into(), "sig".into(), "pk".into(),
                hex_key_image(i as u8 + 1),
                min_ring_members(),
            )
        }).collect();

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
    fn accepts_matching_key_images_count() {
        // 3 inputs, 3 key images -- should pass the count check
        let tx = make_confidential_tx(3);
        assert!(
            RingValidator::validate(&tx),
            "TX with matching input/key_image counts should pass"
        );
    }
}
