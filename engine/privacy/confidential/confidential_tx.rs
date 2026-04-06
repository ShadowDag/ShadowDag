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
use crate::engine::privacy::confidential::pedersen_commitment::PedersenCommitment;
use crate::engine::privacy::confidential::bulletproofs::{Bulletproof, BulletproofResult};
use crate::engine::privacy::confidential::pedersen::RealPedersenCommitment;
use crate::engine::privacy::confidential::range_proof::{self, RangeProof};

/// Result of making a transaction confidential
pub struct ConfidentialResult {
    pub commitment_hex: String,
    pub range_proof_ok: bool,
    pub tx_hash:        String,
    pub proof:          Option<BulletproofResult>,
}

pub struct ConfidentialTx;

impl ConfidentialTx {
    /// Hide all output amounts in a transaction
    pub fn hide_amount(tx: &Transaction) -> Vec<BulletproofResult> {
        tx.outputs.iter().map(|output| {
            Bulletproof::prove(output.amount)
        }).collect()
    }

    /// Hide amounts and return a single confidential result (for first output)
    pub fn hide_and_prove(tx: &Transaction) -> ConfidentialResult {
        let amount = tx.outputs.first().map(|o| o.amount).unwrap_or(0);

        let proof = Bulletproof::prove(amount);
        let commitment_hex = proof.commitment_hex.clone();
        let range_proof_ok = proof.is_valid;

        ConfidentialResult {
            commitment_hex,
            range_proof_ok,
            tx_hash: tx.hash.clone(),
            proof: Some(proof),
        }
    }

    /// Verify a confidential transaction result
    pub fn verify_confidential(result: &ConfidentialResult) -> bool {
        if result.commitment_hex.is_empty() { return false; }
        if !result.range_proof_ok { return false; }

        // Verify the range proof cryptographically
        match &result.proof {
            Some(proof) => Bulletproof::verify_range_proof(proof),
            None => false,
        }
    }

    /// Verify all outputs in a transaction have valid range proofs
    pub fn verify_all_outputs(proofs: &[BulletproofResult]) -> bool {
        if proofs.is_empty() { return false; }
        proofs.iter().all(Bulletproof::verify_range_proof)
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
        input_commitments:  &[String],
        output_commitments: &[String],
        fee_commitment:     &str,
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
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};

    fn make_tx(amount: u64) -> Transaction {
        Transaction {
            hash: "test_ct_tx".to_string(),
            inputs: vec![],
            outputs: vec![TxOutput { address: "addr".into(), amount, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    #[test]
    fn hide_and_prove_valid() {
        let tx = make_tx(5000);
        let result = ConfidentialTx::hide_and_prove(&tx);
        assert!(result.range_proof_ok);
        assert!(!result.commitment_hex.is_empty());
    }

    #[test]
    fn verify_confidential_passes() {
        let tx = make_tx(1000);
        let result = ConfidentialTx::hide_and_prove(&tx);
        assert!(ConfidentialTx::verify_confidential(&result));
    }

    #[test]
    fn hide_all_outputs() {
        let tx = Transaction {
            hash: "multi".into(),
            inputs: vec![],
            outputs: vec![
                TxOutput { address: "a".into(), amount: 100, commitment: None, range_proof: None, ephemeral_pubkey: None },
                TxOutput { address: "b".into(), amount: 200, commitment: None, range_proof: None, ephemeral_pubkey: None },
                TxOutput { address: "c".into(), amount: 300, commitment: None, range_proof: None, ephemeral_pubkey: None },
            ],
            fee: 1,
            timestamp: 1000,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
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
}
