// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Confidential (RingCT) transaction verification for consensus.
//!
//! Pure: reads the UTXO set's `okey:`/`ki:` stores but performs NO mutation.
//! Two worlds: a confidential tx spends confidential outputs only; double-spend
//! is prevented solely by key-image uniqueness. The amount is hidden — soundness
//! comes from the dual-key CLSAG (binds the spend key AND the commitment offset)
//! plus the homomorphic balance `Σ C'_in == Σ C_out + fee·H` and per-output range
//! proofs. SECURITY: external cryptographic review required before mainnet.

use crate::config::node::node_config::NetworkMode;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::transaction::tx_hash::TxHash;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::engine::privacy::confidential::pedersen::RealPedersenCommitment;
use crate::engine::privacy::confidential::range_proof;
use crate::engine::privacy::ringct::dual_clsag;
use crate::engine::privacy::ringct::tx_confidential::{
    parse_confidential_input, parse_confidential_output,
};
use crate::errors::StorageError;
use std::collections::HashSet;

fn err(msg: String) -> StorageError {
    StorageError::Other(msg)
}

/// Verify all confidential aspects of one tx. `seen_ki` accumulates key images
/// across the block for intra-block double-spend detection. No chain mutation.
pub fn verify_confidential_tx(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    network: &NetworkMode,
    seen_ki: &mut HashSet<String>,
) -> Result<(), StorageError> {
    if tx.inputs.is_empty() || tx.outputs.is_empty() {
        return Err(err(format!(
            "confidential tx {} empty inputs/outputs",
            tx.hash
        )));
    }

    let msg = TxHash::confidential_signing_message_for_network(tx, network);

    // ── Inputs: ring authenticity + CLSAG + key-image uniqueness ──
    let mut pseudo_outs = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let view = parse_confidential_input(input)
            .ok_or_else(|| err(format!("confidential tx {}: malformed input", tx.hash)))?;

        // Every ring member must be a real on-chain output with the authentic
        // commitment (binds P AND C). `ring_members` is present because the
        // parse succeeded.
        let members = input
            .ring_members
            .as_ref()
            .ok_or_else(|| err(format!("confidential tx {}: missing ring_members", tx.hash)))?;
        for (member, p_hex) in view.ring.iter().zip(members.iter()) {
            let c_hex = hex::encode(member.commitment.compress().as_bytes());
            match utxo_set.output_key_commitment(p_hex) {
                Some(recorded) if recorded == c_hex => {}
                _ => {
                    return Err(err(format!(
                        "confidential tx {}: ring member not a real output (or commitment mismatch)",
                        tx.hash
                    )))
                }
            }
        }

        // Key image: matches signature, unseen on-chain, unique within block.
        let ki_hex = hex::encode(view.key_image.compress().as_bytes());
        if ki_hex != hex::encode(view.signature.key_image.as_bytes()) {
            return Err(err(format!("confidential tx {}: key image mismatch", tx.hash)));
        }
        if utxo_set.key_image_seen(&ki_hex) {
            return Err(err(format!(
                "confidential tx {}: key image already spent",
                tx.hash
            )));
        }
        if !seen_ki.insert(ki_hex) {
            return Err(err(format!(
                "confidential tx {}: duplicate key image in block",
                tx.hash
            )));
        }

        // Dual-key CLSAG over the canonical message.
        if !dual_clsag::verify(&msg, &view.ring, &view.pseudo_out, &view.signature) {
            return Err(err(format!(
                "confidential tx {}: CLSAG verify failed",
                tx.hash
            )));
        }

        pseudo_outs.push(view.pseudo_out);
    }

    // ── Outputs: range proofs ──
    let mut output_commitments = Vec::with_capacity(tx.outputs.len());
    for output in &tx.outputs {
        let view = parse_confidential_output(output)
            .ok_or_else(|| err(format!("confidential tx {}: malformed output", tx.hash)))?;
        if !range_proof::verify(&view.commitment, &view.range_proof) {
            return Err(err(format!(
                "confidential tx {}: range proof failed",
                tx.hash
            )));
        }
        output_commitments.push(view.commitment);
    }

    // ── Homomorphic balance: Σ C'_in == Σ C_out + fee·H ──
    if !RealPedersenCommitment::verify_balance(&pseudo_outs, &output_commitments, tx.fee) {
        return Err(err(format!(
            "confidential tx {}: commitments do not balance",
            tx.hash
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{TxInput, TxOutput, TxType};
    use crate::engine::privacy::confidential::pedersen::generator_h;
    use crate::engine::privacy::confidential::range_proof::prove;
    use crate::engine::privacy::ringct::dual_clsag::RingMember;
    use crate::engine::privacy::ringct::serialization::range_proof_to_hex;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    fn hexp(p: &RistrettoPoint) -> String {
        hex::encode(p.compress().as_bytes())
    }

    fn net() -> NetworkMode {
        NetworkMode::Mainnet
    }

    /// Build a valid 1-input / 1-output confidential tx (amount `amt`, fee 0),
    /// seeding the ring members into `okey:`. Ring size 4, signer at index 1.
    /// Balance holds because the single output reuses the pseudo-output blinding.
    fn valid_conf_tx(set: &UtxoSet, amt: u64) -> Transaction {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();

        let mut ring = Vec::new();
        for _ in 0..4 {
            let sk = Scalar::random(&mut OsRng);
            let bl = Scalar::random(&mut OsRng);
            let pk = sk * g;
            let c = Scalar::from(amt) * h + bl * g;
            set.record_output_key(&hexp(&pk), &hexp(&c)).unwrap();
            ring.push(RingMember {
                public_key: pk,
                commitment: c,
            });
        }
        let idx = 1usize;
        let spend = Scalar::random(&mut OsRng);
        let r_in = Scalar::random(&mut OsRng);
        let pk = spend * g;
        let c_in = Scalar::from(amt) * h + r_in * g;
        set.record_output_key(&hexp(&pk), &hexp(&c_in)).unwrap();
        ring[idx] = RingMember {
            public_key: pk,
            commitment: c_in,
        };

        let r_prime = Scalar::random(&mut OsRng);
        let pseudo = Scalar::from(amt) * h + r_prime * g;
        let z = r_in - r_prime;

        // Single output: amount = amt, blinding = r_prime ⇒ C_out == pseudo, fee 0.
        let r_out = r_prime;
        let out_commit = Scalar::from(amt) * h + r_out * g;
        let proof = prove(amt, &r_out);
        let one_time = Scalar::random(&mut OsRng) * g;
        let eph = Scalar::random(&mut OsRng) * g;

        let mut tx = Transaction {
            hash: "c".repeat(64),
            inputs: vec![TxInput {
                txid: "0".repeat(64),
                index: 0,
                owner: String::new(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: Some(ring.iter().map(|m| hexp(&m.public_key)).collect()),
                ring_signature: None,
                ring_commitments: Some(ring.iter().map(|m| hexp(&m.commitment)).collect()),
                pseudo_commitment: Some(hexp(&pseudo)),
            }],
            outputs: vec![TxOutput {
                address: "SD1s".into(),
                amount: 0,
                commitment: Some(hexp(&out_commit)),
                range_proof: Some(range_proof_to_hex(&proof)),
                ephemeral_pubkey: Some(hexp(&eph)),
                one_time_pubkey: Some(hexp(&one_time)),
                encrypted_amount: None,
            }],
            fee: 0,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Confidential,
            payload_hash: None,
            ..Default::default()
        };
        // Key image is deterministic; set it BEFORE computing the message.
        let ki = dual_clsag::key_image(&spend, &pk);
        tx.inputs[0].key_image = Some(hexp(&ki));
        let msg = TxHash::confidential_signing_message_for_network(&tx, &net());
        let sig = dual_clsag::sign(&msg, &ring, &pseudo, idx, &spend, &z).unwrap();
        tx.inputs[0].ring_signature = Some(dual_clsag::to_hex(&sig));
        tx
    }

    #[test]
    fn accepts_valid_confidential_tx() {
        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100);
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_ok());
    }

    #[test]
    fn rejects_unbalanced() {
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let bad = Scalar::from(999u64) * h + Scalar::random(&mut OsRng) * g;
        tx.outputs[0].commitment = Some(hexp(&bad));
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_ring_member_not_recorded() {
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        let stray = Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        tx.inputs[0].ring_members.as_mut().unwrap()[0] = hexp(&stray);
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_commitment_mismatch_for_real_pubkey() {
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let fake_c = Scalar::from(100u64) * h + Scalar::random(&mut OsRng) * g;
        tx.inputs[0].ring_commitments.as_mut().unwrap()[0] = hexp(&fake_c);
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_already_spent_key_image() {
        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100);
        let ki = tx.inputs[0].key_image.clone().unwrap();
        set.record_key_image(&ki).unwrap();
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_duplicate_key_image_in_block() {
        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100);
        let mut seen = HashSet::new();
        seen.insert(tx.inputs[0].key_image.clone().unwrap());
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_tampered_signature() {
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        tx.inputs[0].ring_signature = Some("00".repeat(200));
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn rejects_bad_range_proof() {
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        let other = prove(50u64, &Scalar::random(&mut OsRng));
        tx.outputs[0].range_proof = Some(range_proof_to_hex(&other));
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err());
    }

    #[test]
    fn apply_records_ki_okey_then_double_spend_rejected() {
        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100);

        // Valid before applying.
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_ok());

        // Apply the block (single confidential tx) via the LIVE apply path.
        set.apply_block_dag_ordered(std::slice::from_ref(&tx), 1, "blockhash0")
            .unwrap();

        // Key image recorded; one-time output key → commitment recorded.
        let ki = tx.inputs[0].key_image.clone().unwrap();
        assert!(set.key_image_seen(&ki), "key image must be recorded on apply");
        let otk = tx.outputs[0].one_time_pubkey.clone().unwrap();
        assert_eq!(
            set.output_key_commitment(&otk),
            tx.outputs[0].commitment.clone(),
            "output one-time key must map to its commitment"
        );

        // Re-spending the same key image now fails (cross-block double-spend).
        let mut seen2 = HashSet::new();
        assert!(
            verify_confidential_tx(&tx, &set, &net(), &mut seen2).is_err(),
            "key image already spent must be rejected"
        );
    }

    #[test]
    fn apply_advances_confidential_output_index() {
        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100); // one confidential output
        let before = set.confidential_output_count();
        set.apply_block_dag_ordered(std::slice::from_ref(&tx), 1, "blk")
            .unwrap();
        assert_eq!(set.confidential_output_count(), before + 1);
        let last = set.confidential_output_count() - 1;
        assert_eq!(
            set.confidential_output_at(last),
            tx.outputs[0].one_time_pubkey.clone()
        );
    }
}
