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
        // Each input must have ring_members with at least MIN_RING_SIZE entries
        const MIN_RING_SIZE: usize = 4;  // Minimum 4 decoys for meaningful privacy
        const MAX_RING_SIZE: usize = 64; // Cap to prevent DoS
        for input in &tx.inputs {
            if let Some(ref members) = input.ring_members {
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
