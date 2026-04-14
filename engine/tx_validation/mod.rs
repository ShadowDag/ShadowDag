// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

pub const MIN_FEE: u64 = 100;
pub const MAX_TX_SIZE_BYTES: usize = 100_000;
pub const MAX_INPUTS: usize = 1_000;
pub const MAX_OUTPUTS: usize = 1_000;
/// Dust limit: outputs below this threshold are rejected to prevent
/// UTXO bloat attacks. 546 sats matches Bitcoin's standard dust limit.
pub const DUST_LIMIT: u64 = 546;

/// Validation layers — ordered from cheapest to most expensive.
///
/// ```text
/// L1 Network    → size, format, dust, limits        (no DB, no crypto)
/// L2 Structural → hash, signatures, merkle root     (crypto, no state)
/// L3 Consensus  → PoW, difficulty, GHOSTDAG rules   (chain state, no UTXO)
/// L4 Execution  → UTXO lookup, balance, fees        (full state)
/// ```
///
/// Validation MUST proceed in order: L1 → L2 → L3 → L4.
/// An L1 failure rejects immediately without wasting crypto/DB resources.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationLayer {
    /// L1: Cheap sanity — no crypto, no DB
    Network,
    /// L2: Structural integrity — crypto verification, no state
    Structural,
    /// L3: Consensus rules — chain-level state
    Consensus,
    /// L4: Execution — UTXO state, balance, fees
    Execution,
    /// Privacy-specific checks (ring sig, key images, range proofs)
    Privacy,
}

// Keep backward compat alias
pub type ValidationStage = ValidationLayer;

#[derive(Debug, Clone, PartialEq)]
pub enum TxValidationError {
    EmptyHash,
    EmptyOutputs,
    OversizedTransaction,
    TooManyInputs,
    TooManyOutputs,
    ZeroOutputAmount,
    DustOutput(u64),
    NegativeOutputAmount,
    InvalidSignature,
    InputNotFound(String),
    AlreadySpent(String),
    InsufficientFunds,
    InvalidPrivacyProof,
    DuplicateKeyImage(String),
    InvalidRingSignature,
    InvalidRangeProof,
    InvalidCommitmentBalance,
    EmptyKeyImage,
    RingSizeTooSmall(usize),
    KeyImageCountMismatch { expected: usize, actual: usize },
    RingSizeCountMismatch { expected: usize, actual: usize },
    FeeBelowMinimum(u64),
    DuplicateInput(String),
}

impl TxValidationError {
    /// Which validation layer detected this error.
    /// L1 errors are cheap to detect and should reject first.
    pub fn layer(&self) -> ValidationLayer {
        match self {
            // L1 Network — cheap sanity, no crypto
            TxValidationError::EmptyHash
            | TxValidationError::EmptyOutputs
            | TxValidationError::OversizedTransaction
            | TxValidationError::TooManyInputs
            | TxValidationError::TooManyOutputs
            | TxValidationError::ZeroOutputAmount
            | TxValidationError::NegativeOutputAmount
            | TxValidationError::DuplicateInput(_)
            | TxValidationError::DustOutput(_) => ValidationLayer::Network,

            // L2 Structural — crypto verification
            TxValidationError::InvalidSignature => ValidationLayer::Structural,

            // L4 Execution — UTXO state
            TxValidationError::InputNotFound(_)
            | TxValidationError::AlreadySpent(_)
            | TxValidationError::InsufficientFunds
            | TxValidationError::FeeBelowMinimum(_) => ValidationLayer::Execution,

            // Privacy layer
            TxValidationError::InvalidPrivacyProof
            | TxValidationError::DuplicateKeyImage(_)
            | TxValidationError::InvalidRingSignature
            | TxValidationError::InvalidRangeProof
            | TxValidationError::InvalidCommitmentBalance
            | TxValidationError::EmptyKeyImage
            | TxValidationError::RingSizeTooSmall(_)
            | TxValidationError::KeyImageCountMismatch { .. }
            | TxValidationError::RingSizeCountMismatch { .. } => ValidationLayer::Privacy,
        }
    }

    /// Backward compat
    pub fn stage(&self) -> ValidationLayer {
        self.layer()
    }
}

impl std::fmt::Display for TxValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxValidationError::EmptyHash => write!(f, "empty hash"),
            TxValidationError::EmptyOutputs => write!(f, "no outputs"),
            TxValidationError::OversizedTransaction => write!(f, "tx too large"),
            TxValidationError::TooManyInputs => write!(f, "too many inputs"),
            TxValidationError::TooManyOutputs => write!(f, "too many outputs"),
            TxValidationError::ZeroOutputAmount => write!(f, "output amount is zero"),
            TxValidationError::NegativeOutputAmount => write!(f, "output amount negative"),
            TxValidationError::InvalidSignature => write!(f, "invalid signature"),
            TxValidationError::InputNotFound(k) => write!(f, "input not found: {}", k),
            TxValidationError::AlreadySpent(k) => write!(f, "already spent: {}", k),
            TxValidationError::InsufficientFunds => write!(f, "insufficient funds"),
            TxValidationError::InvalidPrivacyProof => write!(f, "invalid privacy proof"),
            TxValidationError::FeeBelowMinimum(fee) => write!(f, "fee {} < min {}", fee, MIN_FEE),
            TxValidationError::DuplicateInput(k) => write!(f, "duplicate input: {}", k),
            TxValidationError::DustOutput(amt) => write!(f, "dust output: {} below minimum", amt),
            TxValidationError::DuplicateKeyImage(ki) => write!(f, "duplicate key image: {}", ki),
            TxValidationError::InvalidRingSignature => write!(f, "invalid ring signature"),
            TxValidationError::InvalidRangeProof => write!(f, "invalid range proof"),
            TxValidationError::InvalidCommitmentBalance => write!(f, "commitment balance mismatch"),
            TxValidationError::EmptyKeyImage => write!(f, "empty key image in confidential tx"),
            TxValidationError::RingSizeTooSmall(n) => write!(f, "ring size {} below minimum 3", n),
            TxValidationError::KeyImageCountMismatch { expected, actual } => {
                write!(f, "key_images count {} != input count {}", actual, expected)
            }
            TxValidationError::RingSizeCountMismatch { expected, actual } => {
                write!(f, "ring_sizes count {} != input count {}", actual, expected)
            }
        }
    }
}

pub type TxValidationResult = Result<(), TxValidationError>;

#[derive(Debug, Clone)]
pub struct TxValidationInput {
    pub hash: String,
    pub input_count: usize,
    pub output_count: usize,
    pub output_amounts: Vec<u64>,
    pub input_keys: Vec<String>,
    pub fee: u64,
    pub size_bytes: usize,
    pub has_signature: bool,
    pub has_privacy_proof: bool,
    pub is_coinbase: bool,
    /// Key images for each input (confidential TXs only)
    pub key_images: Vec<String>,
    /// Ring size for each input (confidential TXs only)
    pub ring_sizes: Vec<usize>,
    /// Whether outputs have valid commitments
    pub has_commitments: bool,
    /// Whether outputs have valid range proofs
    pub has_range_proofs: bool,
}

pub struct TxValidationPipeline;

impl TxValidationPipeline {
    pub fn validate(
        tx: &TxValidationInput,
        spent_inputs: &std::collections::HashSet<String>,
        available_inputs: &std::collections::HashSet<String>,
    ) -> TxValidationResult {
        Self::validate_syntax(tx)?;

        Self::validate_signature(tx)?;

        if !tx.is_coinbase {
            Self::validate_utxo(tx, spent_inputs, available_inputs)?;
        }

        Self::validate_privacy(tx)?;

        Self::validate_fee(tx)?;
        Ok(())
    }

    pub fn validate_syntax(tx: &TxValidationInput) -> TxValidationResult {
        if tx.hash.is_empty() {
            return Err(TxValidationError::EmptyHash);
        }
        if tx.output_count == 0 && !tx.is_coinbase {
            return Err(TxValidationError::EmptyOutputs);
        }
        if tx.size_bytes > MAX_TX_SIZE_BYTES {
            return Err(TxValidationError::OversizedTransaction);
        }
        if tx.input_count > MAX_INPUTS {
            return Err(TxValidationError::TooManyInputs);
        }
        if tx.output_count > MAX_OUTPUTS {
            return Err(TxValidationError::TooManyOutputs);
        }

        for &amount in &tx.output_amounts {
            if amount == 0 {
                return Err(TxValidationError::ZeroOutputAmount);
            }
            // Dust limit: reject tiny outputs that bloat the UTXO set.
            // Coinbase outputs are exempt (they follow emission rules).
            if !tx.is_coinbase && amount < DUST_LIMIT {
                return Err(TxValidationError::DustOutput(amount));
            }
        }

        let mut seen = std::collections::HashSet::new();
        for key in &tx.input_keys {
            if !seen.insert(key) {
                return Err(TxValidationError::DuplicateInput(key.clone()));
            }
        }

        Ok(())
    }

    pub fn validate_signature(tx: &TxValidationInput) -> TxValidationResult {
        if !tx.is_coinbase && !tx.has_signature {
            return Err(TxValidationError::InvalidSignature);
        }
        Ok(())
    }

    pub fn validate_utxo(
        tx: &TxValidationInput,
        spent_inputs: &std::collections::HashSet<String>,
        available_inputs: &std::collections::HashSet<String>,
    ) -> TxValidationResult {
        for key in &tx.input_keys {
            if spent_inputs.contains(key) {
                return Err(TxValidationError::AlreadySpent(key.clone()));
            }
            if !available_inputs.contains(key) {
                return Err(TxValidationError::InputNotFound(key.clone()));
            }
        }
        Ok(())
    }

    /// Minimum ring size to ensure sender ambiguity (Monero uses 11+)
    pub const MIN_RING_SIZE: usize = 3;

    pub fn validate_privacy(tx: &TxValidationInput) -> TxValidationResult {
        if !tx.has_privacy_proof {
            return Ok(());
        }

        // 0. key_images and ring_sizes vectors must match input_count exactly.
        //    Without this check, a confidential TX with input_count > 0 but
        //    empty key_images=[] and ring_sizes=[] would pass all loop checks
        //    vacuously.
        let input_count = tx.input_count;
        if tx.key_images.len() != input_count {
            return Err(TxValidationError::KeyImageCountMismatch {
                expected: input_count,
                actual: tx.key_images.len(),
            });
        }
        if tx.ring_sizes.len() != input_count {
            return Err(TxValidationError::RingSizeCountMismatch {
                expected: input_count,
                actual: tx.ring_sizes.len(),
            });
        }

        // 1. Every input must have a non-empty key image
        for ki in &tx.key_images {
            if ki.is_empty() {
                return Err(TxValidationError::EmptyKeyImage);
            }
        }

        // 2. No duplicate key images within the same TX (intra-TX double-spend)
        let mut seen_images = std::collections::HashSet::new();
        for ki in &tx.key_images {
            if !seen_images.insert(ki.clone()) {
                return Err(TxValidationError::DuplicateKeyImage(ki.clone()));
            }
        }

        // 3. Ring size must be at least MIN_RING_SIZE for each input
        for &rs in &tx.ring_sizes {
            if rs < Self::MIN_RING_SIZE {
                return Err(TxValidationError::RingSizeTooSmall(rs));
            }
        }

        // 4. Confidential outputs must have commitments
        if !tx.has_commitments {
            return Err(TxValidationError::InvalidCommitmentBalance);
        }

        // 5. Confidential outputs must have range proofs
        if !tx.has_range_proofs {
            return Err(TxValidationError::InvalidRangeProof);
        }

        Ok(())
    }

    pub fn validate_fee(tx: &TxValidationInput) -> TxValidationResult {
        if !tx.is_coinbase && tx.fee < MIN_FEE {
            return Err(TxValidationError::FeeBelowMinimum(tx.fee));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn valid_tx() -> TxValidationInput {
        TxValidationInput {
            hash: "abc123".into(),
            input_count: 1,
            output_count: 1,
            output_amounts: vec![1_000_000],
            input_keys: vec!["prev:0".into()],
            fee: MIN_FEE,
            size_bytes: 500,
            has_signature: true,
            has_privacy_proof: false,
            is_coinbase: false,
            key_images: Vec::new(),
            ring_sizes: Vec::new(),
            has_commitments: false,
            has_range_proofs: false,
        }
    }

    fn available() -> HashSet<String> {
        vec!["prev:0".to_string()].into_iter().collect()
    }

    #[test]
    fn valid_tx_passes_all_stages() {
        let tx = valid_tx();
        let spent = HashSet::new();
        let avail = available();
        assert!(TxValidationPipeline::validate(&tx, &spent, &avail).is_ok());
    }

    #[test]
    fn empty_hash_fails_syntax() {
        let mut tx = valid_tx();
        tx.hash = String::new();
        assert_eq!(
            TxValidationPipeline::validate_syntax(&tx),
            Err(TxValidationError::EmptyHash)
        );
    }

    #[test]
    fn zero_output_fails_syntax() {
        let mut tx = valid_tx();
        tx.output_amounts = vec![0];
        assert_eq!(
            TxValidationPipeline::validate_syntax(&tx),
            Err(TxValidationError::ZeroOutputAmount)
        );
    }

    #[test]
    fn missing_signature_fails() {
        let mut tx = valid_tx();
        tx.has_signature = false;
        let spent = HashSet::new();
        let avail = available();
        assert_eq!(
            TxValidationPipeline::validate(&tx, &spent, &avail),
            Err(TxValidationError::InvalidSignature)
        );
    }

    #[test]
    fn already_spent_fails_utxo() {
        let tx = valid_tx();
        let spent: HashSet<String> = vec!["prev:0".to_string()].into_iter().collect();
        let avail = available();
        assert_eq!(
            TxValidationPipeline::validate(&tx, &spent, &avail),
            Err(TxValidationError::AlreadySpent("prev:0".into()))
        );
    }

    #[test]
    fn low_fee_fails() {
        let mut tx = valid_tx();
        tx.fee = 0;
        let spent = HashSet::new();
        let avail = available();
        assert_eq!(
            TxValidationPipeline::validate(&tx, &spent, &avail),
            Err(TxValidationError::FeeBelowMinimum(0))
        );
    }

    #[test]
    fn duplicate_input_fails_syntax() {
        let mut tx = valid_tx();
        tx.input_keys = vec!["prev:0".into(), "prev:0".into()];
        tx.input_count = 2;
        assert!(TxValidationPipeline::validate_syntax(&tx).is_err());
    }

    // ── Privacy validation tests ──────────────────────────────────────

    fn confidential_tx() -> TxValidationInput {
        TxValidationInput {
            hash: "ct_abc123".into(),
            input_count: 1,
            output_count: 1,
            output_amounts: vec![1_000_000],
            input_keys: vec!["prev:0".into()],
            fee: MIN_FEE,
            size_bytes: 500,
            has_signature: true,
            has_privacy_proof: true,
            is_coinbase: false,
            key_images: vec!["ki_abc123def456".into()],
            ring_sizes: vec![11],
            has_commitments: true,
            has_range_proofs: true,
        }
    }

    #[test]
    fn valid_confidential_tx_passes() {
        let tx = confidential_tx();
        assert!(TxValidationPipeline::validate_privacy(&tx).is_ok());
    }

    #[test]
    fn confidential_tx_empty_key_image_fails() {
        let mut tx = confidential_tx();
        tx.key_images = vec!["".into()];
        assert_eq!(
            TxValidationPipeline::validate_privacy(&tx),
            Err(TxValidationError::EmptyKeyImage)
        );
    }

    #[test]
    fn confidential_tx_duplicate_key_image_fails() {
        let mut tx = confidential_tx();
        tx.input_count = 2;
        tx.key_images = vec!["ki_same".into(), "ki_same".into()];
        tx.ring_sizes = vec![11, 11];
        assert_eq!(
            TxValidationPipeline::validate_privacy(&tx),
            Err(TxValidationError::DuplicateKeyImage("ki_same".into()))
        );
    }

    #[test]
    fn confidential_tx_ring_too_small_fails() {
        let mut tx = confidential_tx();
        tx.ring_sizes = vec![2]; // below MIN_RING_SIZE (3)
        assert_eq!(
            TxValidationPipeline::validate_privacy(&tx),
            Err(TxValidationError::RingSizeTooSmall(2))
        );
    }

    #[test]
    fn confidential_tx_missing_commitments_fails() {
        let mut tx = confidential_tx();
        tx.has_commitments = false;
        assert_eq!(
            TxValidationPipeline::validate_privacy(&tx),
            Err(TxValidationError::InvalidCommitmentBalance)
        );
    }

    #[test]
    fn confidential_tx_missing_range_proofs_fails() {
        let mut tx = confidential_tx();
        tx.has_range_proofs = false;
        assert_eq!(
            TxValidationPipeline::validate_privacy(&tx),
            Err(TxValidationError::InvalidRangeProof)
        );
    }

    #[test]
    fn transparent_tx_skips_privacy_checks() {
        let tx = valid_tx(); // has_privacy_proof = false
        assert!(TxValidationPipeline::validate_privacy(&tx).is_ok());
    }

    #[test]
    fn confidential_tx_empty_key_images_with_inputs_fails() {
        // Regression: input_count > 0 with empty key_images should not pass vacuously
        let mut tx = confidential_tx();
        tx.input_count = 2;
        tx.key_images = vec![];
        tx.ring_sizes = vec![];
        assert_eq!(
            TxValidationPipeline::validate_privacy(&tx),
            Err(TxValidationError::KeyImageCountMismatch {
                expected: 2,
                actual: 0
            })
        );
    }

    #[test]
    fn confidential_tx_ring_sizes_count_mismatch_fails() {
        let mut tx = confidential_tx();
        tx.input_count = 2;
        tx.key_images = vec!["ki_1".into(), "ki_2".into()];
        tx.ring_sizes = vec![11]; // only 1 ring size for 2 inputs
        assert_eq!(
            TxValidationPipeline::validate_privacy(&tx),
            Err(TxValidationError::RingSizeCountMismatch {
                expected: 2,
                actual: 1
            })
        );
    }
}
