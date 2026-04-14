// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Confidential Transactions — Hide transaction amounts on-chain.
//
// Each output amount is replaced with a Pedersen commitment + range proof.
// Observers see the commitment but cannot determine the actual value.
// The range proof proves the value is non-negative (no inflation).
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::transaction::transaction::Transaction;
use crate::engine::privacy::confidential::bulletproofs::{Bulletproof, BulletproofResult};
use crate::engine::privacy::confidential::pedersen::RealPedersenCommitment;
use crate::engine::privacy::confidential::pedersen_commitment::PedersenCommitment;
use crate::engine::privacy::confidential::range_proof::{self, RangeProof};
use crate::errors::CryptoError;

/// Result of making a transaction confidential (legacy format).
///
/// This uses the legacy hash-based `BulletproofResult` from `bulletproofs.rs`.
/// For production, prefer `RealConfidentialResult` which uses real Pedersen
/// commitments (Ristretto points) and Borromean ring signature range proofs.
pub struct ConfidentialResult {
    pub commitment_hex: String,
    pub range_proof_ok: bool,
    pub tx_hash: String,
    pub proof: Option<BulletproofResult>,
}

/// Result of making a transaction confidential using real cryptography.
///
/// Uses `RealPedersenCommitment` (curve25519-dalek Ristretto) for commitments
/// and Borromean ring signature range proofs from `range_proof.rs`.
pub struct RealConfidentialResult {
    pub commitment: RealPedersenCommitment,
    pub range_proof: RangeProof,
    pub tx_hash: String,
}

pub struct ConfidentialTx;

impl ConfidentialTx {
    /// Hide all output amounts in a transaction (LEGACY path).
    ///
    /// Uses the legacy hash-based `Bulletproof::prove()` simulation.
    /// For production, use `hide_amount_real()` which produces real Pedersen
    /// commitments and Borromean range proofs.
    #[allow(deprecated)]
    pub fn hide_amount(tx: &Transaction) -> Vec<BulletproofResult> {
        eprintln!(
            "[WARN] confidential_tx: hide_amount() using LEGACY hash-based Bulletproof \
             simulation for TX {}. For production, use hide_amount_real().",
            tx.hash,
        );
        tx.outputs
            .iter()
            .map(|output| Bulletproof::prove(output.amount))
            .collect()
    }

    /// Hide all output amounts using REAL Pedersen commitments and Borromean range proofs.
    ///
    /// Each output gets a `RealPedersenCommitment` (Ristretto point) and a
    /// `RangeProof` (Borromean ring signatures proving value in [0, 2^64)).
    pub fn hide_amount_real(tx: &Transaction) -> Vec<(RealPedersenCommitment, RangeProof)> {
        tx.outputs
            .iter()
            .map(|output| Self::create_confidential_output_real(output.amount))
            .collect()
    }

    /// Hide amounts and return a single confidential result for the first output (LEGACY path).
    ///
    /// Uses the legacy hash-based `Bulletproof::prove()` simulation.
    /// For production, use `hide_and_prove_real()` which uses real Pedersen
    /// commitments and Borromean range proofs.
    ///
    /// Returns an error when the transaction has no outputs.
    #[allow(deprecated)]
    pub fn hide_and_prove(tx: &Transaction) -> Result<ConfidentialResult, CryptoError> {
        if tx.outputs.is_empty() {
            return Err(CryptoError::Other(
                "cannot create confidential proof for TX with no outputs".into(),
            ));
        }

        eprintln!(
            "[WARN] confidential_tx: hide_and_prove() using LEGACY hash-based Bulletproof \
             simulation for TX {}. For production, use hide_and_prove_real().",
            tx.hash,
        );

        let amount = tx.outputs[0].amount;

        let proof = Bulletproof::prove(amount);
        let commitment_hex = proof.commitment_hex.clone();
        let range_proof_ok = proof.is_valid;

        Ok(ConfidentialResult {
            commitment_hex,
            range_proof_ok,
            tx_hash: tx.hash.clone(),
            proof: Some(proof),
        })
    }

    /// Hide amounts and return a single confidential result for the first output
    /// using REAL Pedersen commitments and Borromean range proofs.
    ///
    /// Returns an error when the transaction has no outputs.
    pub fn hide_and_prove_real(tx: &Transaction) -> Result<RealConfidentialResult, CryptoError> {
        if tx.outputs.is_empty() {
            return Err(CryptoError::Other(
                "cannot create confidential proof for TX with no outputs".into(),
            ));
        }

        let amount = tx.outputs[0].amount;
        let commitment = RealPedersenCommitment::commit_random(amount);
        let rp = range_proof::prove(amount, &commitment.blinding);

        Ok(RealConfidentialResult {
            commitment,
            range_proof: rp,
            tx_hash: tx.hash.clone(),
        })
    }

    /// Verify a confidential transaction result (LEGACY path).
    ///
    /// Uses the legacy hash-based `Bulletproof::verify_range_proof()` simulation.
    /// For production, use `verify_confidential_real()` which uses real
    /// Pedersen commitment opening + Borromean range proof verification.
    ///
    /// NOTE: `tx_hash` binding (i.e. ensuring the proof is bound to a specific
    /// transaction) is performed at a higher layer (block validation / consensus).
    /// This function only checks the cryptographic validity of the commitment
    /// and range proof.
    #[allow(deprecated)]
    pub fn verify_confidential(result: &ConfidentialResult) -> bool {
        if result.commitment_hex.is_empty() {
            return false;
        }
        if !result.range_proof_ok {
            return false;
        }

        // Verify the range proof cryptographically (LEGACY path)
        match &result.proof {
            Some(proof) => Bulletproof::verify_range_proof(proof),
            None => false,
        }
    }

    /// Verify a confidential transaction result using REAL cryptographic verification.
    ///
    /// Checks:
    ///   1. The Pedersen commitment opens to the claimed value with the given blinding
    ///   2. The Borromean range proof proves the committed value is in [0, 2^64)
    pub fn verify_confidential_real(result: &RealConfidentialResult) -> bool {
        // Verify Pedersen commitment opening
        if !RealPedersenCommitment::verify_opening(
            &result.commitment.commitment,
            result.commitment.value,
            &result.commitment.blinding,
        ) {
            return false;
        }

        // Verify Borromean range proof against the commitment
        range_proof::verify(&result.commitment.commitment, &result.range_proof)
    }

    /// Verify all outputs in a transaction have valid range proofs (LEGACY path).
    ///
    /// Uses the legacy hash-based `Bulletproof::verify_range_proof()`.
    /// For production, use `verify_all_outputs_real()`.
    #[allow(deprecated)]
    pub fn verify_all_outputs(proofs: &[BulletproofResult]) -> bool {
        if proofs.is_empty() {
            return false;
        }
        proofs.iter().all(Bulletproof::verify_range_proof)
    }

    /// Verify all outputs using REAL Borromean range proof verification.
    pub fn verify_all_outputs_real(outputs: &[(RealPedersenCommitment, RangeProof)]) -> bool {
        if outputs.is_empty() {
            return false;
        }
        outputs
            .iter()
            .all(|(commitment, proof)| range_proof::verify(&commitment.commitment, proof))
    }

    /// Create a confidential output using REAL Pedersen commitments and
    /// Borromean ring signature range proofs (curve25519-dalek Ristretto).
    ///
    /// Returns the commitment (with opening info) and a range proof that
    /// the value is in [0, 2^64).
    pub fn create_confidential_output_real(value: u64) -> (RealPedersenCommitment, RangeProof) {
        let commitment = RealPedersenCommitment::commit_random(value);
        let proof = range_proof::prove(value, &commitment.blinding);
        (commitment, proof)
    }

    /// Check that sum of input commitments equals sum of output commitments
    /// (conservation of value — no inflation)
    pub fn verify_balance(
        input_commitments: &[String],
        output_commitments: &[String],
        fee_commitment: &str,
    ) -> bool {
        if input_commitments.is_empty() || output_commitments.is_empty() {
            return false;
        }

        // Sum inputs
        let mut input_sum = input_commitments[0].clone();
        for c in &input_commitments[1..] {
            input_sum = match PedersenCommitment::add_commitments(&input_sum, c) {
                Some(s) => s,
                None => return false,
            };
        }

        // Sum outputs + fee
        let mut output_sum = output_commitments[0].clone();
        for c in &output_commitments[1..] {
            output_sum = match PedersenCommitment::add_commitments(&output_sum, c) {
                Some(s) => s,
                None => return false,
            };
        }
        if !fee_commitment.is_empty() {
            output_sum = match PedersenCommitment::add_commitments(&output_sum, fee_commitment) {
                Some(s) => s,
                None => return false,
            };
        }

        // Inputs must equal outputs + fee (homomorphic property)
        input_sum == output_sum
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};

    fn make_tx(amount: u64) -> Transaction {
        Transaction {
            hash: "test_ct_tx".to_string(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "addr".into(),
                amount,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    // ── Legacy path tests (kept for backward compatibility) ──────────

    #[test]
    fn hide_and_prove_valid() {
        let tx = make_tx(5000);
        let result = ConfidentialTx::hide_and_prove(&tx).unwrap();
        assert!(result.range_proof_ok);
        assert!(!result.commitment_hex.is_empty());
    }

    #[test]
    fn verify_confidential_passes() {
        let tx = make_tx(1000);
        let result = ConfidentialTx::hide_and_prove(&tx).unwrap();
        assert!(ConfidentialTx::verify_confidential(&result));
    }

    #[test]
    fn hide_all_outputs() {
        let tx = Transaction {
            hash: "multi".into(),
            inputs: vec![],
            outputs: vec![
                TxOutput {
                    address: "a".into(),
                    amount: 100,
                    commitment: None,
                    range_proof: None,
                    ephemeral_pubkey: None,
                },
                TxOutput {
                    address: "b".into(),
                    amount: 200,
                    commitment: None,
                    range_proof: None,
                    ephemeral_pubkey: None,
                },
                TxOutput {
                    address: "c".into(),
                    amount: 300,
                    commitment: None,
                    range_proof: None,
                    ephemeral_pubkey: None,
                },
            ],
            fee: 1,
            timestamp: 1000,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        let proofs = ConfidentialTx::hide_amount(&tx);
        assert_eq!(proofs.len(), 3);
        assert!(ConfidentialTx::verify_all_outputs(&proofs));
    }

    #[test]
    fn verify_fails_on_empty() {
        let bad = ConfidentialResult {
            commitment_hex: String::new(),
            range_proof_ok: false,
            tx_hash: "x".into(),
            proof: None,
        };
        assert!(!ConfidentialTx::verify_confidential(&bad));
    }

    // ── Real cryptography path tests ────────────────────────────────

    #[test]
    fn hide_and_prove_real_valid() {
        let tx = make_tx(5000);
        let result = ConfidentialTx::hide_and_prove_real(&tx).unwrap();
        assert!(ConfidentialTx::verify_confidential_real(&result));
    }

    #[test]
    fn hide_and_prove_real_rejects_empty_outputs() {
        let tx = Transaction {
            hash: "empty".into(),
            inputs: vec![],
            outputs: vec![],
            fee: 1,
            timestamp: 1000,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        assert!(ConfidentialTx::hide_and_prove_real(&tx).is_err());
    }

    #[test]
    fn hide_all_outputs_real() {
        let tx = Transaction {
            hash: "multi_real".into(),
            inputs: vec![],
            outputs: vec![
                TxOutput {
                    address: "a".into(),
                    amount: 100,
                    commitment: None,
                    range_proof: None,
                    ephemeral_pubkey: None,
                },
                TxOutput {
                    address: "b".into(),
                    amount: 200,
                    commitment: None,
                    range_proof: None,
                    ephemeral_pubkey: None,
                },
                TxOutput {
                    address: "c".into(),
                    amount: 300,
                    commitment: None,
                    range_proof: None,
                    ephemeral_pubkey: None,
                },
            ],
            fee: 1,
            timestamp: 1000,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        let outputs = ConfidentialTx::hide_amount_real(&tx);
        assert_eq!(outputs.len(), 3);
        assert!(ConfidentialTx::verify_all_outputs_real(&outputs));
    }

    #[test]
    fn verify_real_fails_on_empty() {
        assert!(!ConfidentialTx::verify_all_outputs_real(&[]));
    }
}
