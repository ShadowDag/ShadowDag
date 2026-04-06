// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::transaction::transaction::Transaction;
use crate::engine::privacy::ringct::ring_signature::RingSignature;

pub struct RingValidator;

impl RingValidator {
    pub fn validate(tx: &Transaction) -> bool {
        if !RingSignature::verify(tx) {
            return false;
        }

        if tx.outputs.is_empty() {
            return false;
        }

        // Every input in a privacy TX must carry a valid key image.
        // Key images MUST be exactly 32 bytes (64 hex chars).
        // Accepting shorter values (e.g., 9 bytes) breaks untraceability.
        let key_images = RingSignature::key_images(tx);
        if key_images.is_empty() && !tx.inputs.is_empty() {
            return false;
        }
        for ki in &key_images {
            if ki.len() != 64 || !ki.chars().all(|c| c.is_ascii_hexdigit()) {
                return false;
            }
        }

        true
    }

    #[deprecated(since = "1.0", note = "Use validate() instead. quick_validate skips ring signature verification!")]
    pub fn quick_validate(tx: &Transaction) -> bool {
        Self::validate(tx)
    }
}
