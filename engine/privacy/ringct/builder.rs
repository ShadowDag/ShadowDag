// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Confidential (RingCT) transaction builder. Given the spender's secrets and a
//! decoy ring per input, produces a Transaction that passes the consensus gate
//! `verify_confidential_tx`. No amount-encoding for the receiver (sub-project 4b)
//! and no automatic decoy selection / wallet wiring (4c).

use crate::config::node::node_config::NetworkMode;
use crate::domain::address::stealth_address::StealthAddress;
use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
use crate::domain::transaction::tx_hash::TxHash;
use crate::engine::privacy::confidential::pedersen::generator_h;
use crate::engine::privacy::confidential::range_proof;
use crate::engine::privacy::ringct::amount_encoding;
use crate::engine::privacy::ringct::dual_clsag::{self, RingMember};
use crate::engine::privacy::ringct::serialization::range_proof_to_hex;
use crate::errors::CryptoError;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use std::time::{SystemTime, UNIX_EPOCH};

/// What the spender knows about one real input being spent.
pub struct OwnedInput {
    pub spend_secret: Scalar, // x: one-time spend key of the real output
    pub amount: u64,
    pub blinding: Scalar, // r_real: blinding of the real input commitment
    pub ring: Vec<RingMember>, // decoys + real, as (P_i, C_i)
    pub real_index: usize,
}

/// A confidential recipient (stealth target + amount).
pub struct ConfRecipient {
    pub view_pub: RistrettoPoint,
    pub spend_pub: RistrettoPoint,
    pub amount: u64,
}

/// A TRANSPARENT input being SHIELDED (spent into the confidential pool).
pub struct ShieldInput {
    pub txid: String,
    pub index: u32,
    pub owner: String,
    /// PUBLIC amount of the input UTXO — MUST equal the on-chain amount (the
    /// node reads it from the UTXO set; a mismatch is rejected by verify_shield_tx).
    pub amount: u64,
    pub pub_key_hex: String,
    /// Ed25519 signing key that owns this outpoint.
    pub signing_key: ed25519_dalek::SigningKey,
}

fn hexp(p: &RistrettoPoint) -> String {
    hex::encode(p.compress().as_bytes())
}

/// Build a confidential transaction. The returned tx is consensus-valid
/// (passes `verify_confidential_tx`) when the ring members are recorded on-chain.
pub fn build_confidential_transaction(
    inputs: Vec<OwnedInput>,
    recipients: Vec<ConfRecipient>,
    fee: u64,
    network: &NetworkMode,
) -> Result<Transaction, CryptoError> {
    use rand::rngs::OsRng;
    use zeroize::Zeroize;

    if inputs.is_empty() || recipients.is_empty() {
        return Err(CryptoError::Other(
            "confidential tx needs >= 1 input and >= 1 recipient".into(),
        ));
    }
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = generator_h();

    // 1. Amount balance (u128 to avoid overflow).
    let in_sum: u128 = inputs.iter().map(|i| i.amount as u128).sum();
    let out_sum: u128 = recipients.iter().map(|r| r.amount as u128).sum();
    if in_sum != out_sum + fee as u128 {
        return Err(CryptoError::Other(
            "confidential build: inputs != outputs + fee".into(),
        ));
    }
    // Each input's real commitment must open to (amount, blinding).
    for inp in &inputs {
        if inp.real_index >= inp.ring.len() {
            return Err(CryptoError::InvalidRingIndex {
                index: inp.real_index,
                ring_size: inp.ring.len(),
            });
        }
        let expected = Scalar::from(inp.amount) * h + inp.blinding * g;
        if inp.ring[inp.real_index].commitment != expected {
            return Err(CryptoError::Other(
                "confidential build: input commitment does not open to (amount, blinding)".into(),
            ));
        }
    }

    // 2. Outputs: stealth one-time address + derived blinding + commitment +
    //    range proof + encrypted amount. The blinding is derived from the ECDH
    //    shared secret so the recipient can recompute it (so it is NOT free to
    //    choose for balancing — the input side absorbs instead, step 3).
    let n_out = recipients.len();
    let mut out_blinding_sum = Scalar::ZERO;
    let mut tx_outputs = Vec::with_capacity(n_out);
    for (i, r) in recipients.iter().enumerate() {
        let (stealth, ss) = StealthAddress::generate_full_for_network_with_secret(
            &r.view_pub,
            &r.spend_pub,
            network.short_name(),
        )?;
        let blinding = amount_encoding::derive_blinding(&ss, i as u32);
        out_blinding_sum += blinding;
        let c_out = Scalar::from(r.amount) * h + blinding * g;
        let proof = range_proof::prove(r.amount, &blinding);
        let mask = amount_encoding::amount_mask(&ss, i as u32);
        let enc = amount_encoding::encrypt_amount(r.amount, &mask);
        tx_outputs.push(TxOutput {
            address: stealth.one_time_address,
            amount: 0,
            commitment: Some(hexp(&c_out)),
            range_proof: Some(range_proof_to_hex(&proof)),
            ephemeral_pubkey: Some(stealth.ephemeral_pubkey),
            one_time_pubkey: Some(stealth.one_time_pubkey),
            encrypted_amount: Some(amount_encoding::enc_to_hex(&enc)),
        });
    }

    // 3. Pseudo-output blindings: random per input EXCEPT the last input, which
    //    absorbs the difference so Σ r'_in == Σ derived_out_blindings (the H
    //    terms already match because the amounts balance). Requires ≥ 1 input.
    let mut pseudo_blindings: Vec<Scalar> =
        (0..inputs.len()).map(|_| Scalar::random(&mut OsRng)).collect();
    let last = inputs.len() - 1;
    let sum_other_pseudo: Scalar = pseudo_blindings[..last].iter().sum();
    pseudo_blindings[last] = out_blinding_sum - sum_other_pseudo;

    // 4. Inputs: pseudo-output + ring + key image (no signature yet).
    let mut tx_inputs = Vec::with_capacity(inputs.len());
    let mut pseudo_points = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        let pseudo = Scalar::from(inp.amount) * h + pseudo_blindings[i] * g;
        pseudo_points.push(pseudo);
        let ki = dual_clsag::key_image(&inp.spend_secret, &inp.ring[inp.real_index].public_key);
        tx_inputs.push(TxInput {
            txid: "0".repeat(64), // outpoint is meaningless for confidential inputs
            index: i as u32,      // keep (txid,index) distinct per input
            owner: String::new(),
            signature: String::new(),
            pub_key: String::new(),
            key_image: Some(hexp(&ki)),
            ring_members: Some(inp.ring.iter().map(|m| hexp(&m.public_key)).collect()),
            ring_signature: None,
            ring_commitments: Some(inp.ring.iter().map(|m| hexp(&m.commitment)).collect()),
            pseudo_commitment: Some(hexp(&pseudo)),
            shield_blinding: None,
        });
    }

    // Unix epoch MILLISECONDS (confidential tx timestamps are ms).
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut tx = Transaction {
        hash: String::new(),
        inputs: tx_inputs,
        outputs: tx_outputs,
        fee,
        timestamp,
        is_coinbase: false,
        tx_type: TxType::Confidential,
        payload_hash: None,
        ..Default::default()
    };

    // 5. Sign each input (key images already set ⇒ message is stable).
    let msg = TxHash::confidential_signing_message_for_network(&tx, network);
    for (i, inp) in inputs.iter().enumerate() {
        let mut z = inp.blinding - pseudo_blindings[i];
        let sig = dual_clsag::sign(
            &msg,
            &inp.ring,
            &pseudo_points[i],
            inp.real_index,
            &inp.spend_secret,
            &z,
        )
        .map_err(|e| CryptoError::Other(format!("confidential build: clsag sign: {e:?}")))?;
        tx.inputs[i].ring_signature = Some(dual_clsag::to_hex(&sig));
        z.zeroize();
    }
    tx.hash = TxHash::hash_for_network(&tx, network);

    for b in pseudo_blindings.iter_mut() {
        b.zeroize();
    }
    Ok(tx)
}

/// Build a SHIELD transaction: TRANSPARENT inputs -> CONFIDENTIAL outputs.
///
/// The entry point into the confidential pool. Reuses the confidential OUTPUT
/// construction (stealth + Pedersen commitment + range proof + encrypted
/// amount); the transparent input blindings `r_i` are chosen so `Σ r_i == Σ`
/// (derived output blindings), and each input is Ed25519-signed over the
/// transparent signing message. The returned tx passes `verify_shield_tx` when
/// each input's `amount` equals its on-chain UTXO amount.
pub fn build_shield_transaction(
    inputs: Vec<ShieldInput>,
    recipients: Vec<ConfRecipient>,
    fee: u64,
    network: &NetworkMode,
) -> Result<Transaction, CryptoError> {
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;
    use zeroize::Zeroize;

    if inputs.is_empty() || recipients.is_empty() {
        return Err(CryptoError::Other(
            "shield tx needs >= 1 input and >= 1 recipient".into(),
        ));
    }
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = generator_h();

    // Amount balance: Σ public input amounts == Σ recipient amounts + fee.
    let in_sum: u128 = inputs.iter().map(|i| i.amount as u128).sum();
    let out_sum: u128 = recipients.iter().map(|r| r.amount as u128).sum();
    if in_sum != out_sum + fee as u128 {
        return Err(CryptoError::Other(
            "shield build: inputs != outputs + fee".into(),
        ));
    }

    // Confidential outputs (identical to build_confidential_transaction).
    let mut out_blinding_sum = Scalar::ZERO;
    let mut tx_outputs = Vec::with_capacity(recipients.len());
    for (i, r) in recipients.iter().enumerate() {
        let (stealth, ss) = StealthAddress::generate_full_for_network_with_secret(
            &r.view_pub,
            &r.spend_pub,
            network.short_name(),
        )?;
        let blinding = amount_encoding::derive_blinding(&ss, i as u32);
        out_blinding_sum += blinding;
        let c_out = Scalar::from(r.amount) * h + blinding * g;
        let proof = range_proof::prove(r.amount, &blinding);
        let mask = amount_encoding::amount_mask(&ss, i as u32);
        let enc = amount_encoding::encrypt_amount(r.amount, &mask);
        tx_outputs.push(TxOutput {
            address: stealth.one_time_address,
            amount: 0,
            commitment: Some(hexp(&c_out)),
            range_proof: Some(range_proof_to_hex(&proof)),
            ephemeral_pubkey: Some(stealth.ephemeral_pubkey),
            one_time_pubkey: Some(stealth.one_time_pubkey),
            encrypted_amount: Some(amount_encoding::enc_to_hex(&enc)),
        });
    }

    // Transparent input blindings: random per input EXCEPT the last, which
    // absorbs the difference so Σ r_i == Σ derived_out_blindings (the H/amount
    // terms already balance). C_in = A_i·H + r_i·G is reconstructed by the node.
    let mut in_blindings: Vec<Scalar> =
        (0..inputs.len()).map(|_| Scalar::random(&mut OsRng)).collect();
    let last = inputs.len() - 1;
    let sum_other: Scalar = in_blindings[..last].iter().sum();
    in_blindings[last] = out_blinding_sum - sum_other;

    let mut tx_inputs = Vec::with_capacity(inputs.len());
    for (i, inp) in inputs.iter().enumerate() {
        tx_inputs.push(TxInput {
            txid: inp.txid.clone(),
            index: inp.index,
            owner: inp.owner.clone(),
            signature: String::new(),
            pub_key: inp.pub_key_hex.clone(),
            key_image: None,
            ring_members: None,
            ring_signature: None,
            ring_commitments: None,
            pseudo_commitment: None,
            shield_blinding: Some(hex::encode(in_blindings[i].to_bytes())),
        });
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut tx = Transaction {
        hash: String::new(),
        inputs: tx_inputs,
        outputs: tx_outputs,
        fee,
        timestamp,
        is_coinbase: false,
        tx_type: TxType::Shield,
        payload_hash: None,
        ..Default::default()
    };
    tx.hash = TxHash::hash_for_network(&tx, network);

    // Ed25519 sign each input over the transparent signing message (hash is set).
    let msg = TxHash::signing_message_for_network(&tx, network);
    for (i, inp) in inputs.iter().enumerate() {
        let sig = inp.signing_key.sign(&msg);
        tx.inputs[i].signature = hex::encode(sig.to_bytes());
    }

    for b in in_blindings.iter_mut() {
        b.zeroize();
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::engine::privacy::ringct::confidential_consensus::{
        verify_confidential_tx, verify_shield_tx,
    };
    use rand::rngs::OsRng;
    use std::collections::HashSet;

    #[test]
    fn built_shield_tx_passes_the_consensus_gate() {
        use crate::domain::transaction::transaction::{Transaction as Tx, TxOutput, TxType};
        use ed25519_dalek::SigningKey;
        use sha2::{Digest, Sha256};

        let set = UtxoSet::new_empty();
        // Keypair + mainnet address.
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let pk_hex = hex::encode(pk.to_bytes());
        let mut ah = Sha256::new();
        ah.update(b"ShadowDAG_Addr_v1");
        ah.update(pk.to_bytes());
        let address = format!("SD1{}", hex::encode(&ah.finalize()[..20]));

        // Seed a transparent coinbase of 1000 owned by `address`.
        let cb_hash = "a".repeat(64);
        let mut cb = Tx::new_coinbase(cb_hash.clone(), vec![TxOutput::new(address.clone(), 1000)], 0, 1);
        cb.hash = cb_hash.clone();
        set.apply_block_dag_ordered(std::slice::from_ref(&cb), 0, "cbblk").unwrap();

        // Recipient stealth pubkeys + shield the whole input (minus fee).
        let g = RISTRETTO_BASEPOINT_POINT;
        let view_pub = Scalar::random(&mut OsRng) * g;
        let spend_pub = Scalar::random(&mut OsRng) * g;
        let fee = 10u64;
        let tx = build_shield_transaction(
            vec![ShieldInput {
                txid: cb_hash,
                index: 0,
                owner: address,
                amount: 1000,
                pub_key_hex: pk_hex,
                signing_key: sk,
            }],
            vec![ConfRecipient { view_pub, spend_pub, amount: 1000 - fee }],
            fee,
            &NetworkMode::Mainnet,
        )
        .unwrap();

        assert_eq!(tx.tx_type, TxType::Shield);
        assert!(
            verify_shield_tx(&tx, &set, &NetworkMode::Mainnet).is_ok(),
            "a built shield tx must pass verify_shield_tx (build -> verify round-trip)"
        );
    }

    /// Build one OwnedInput holding `amount`: a ring of `ring_size` real
    /// on-chain outputs (all recorded into `set`'s okey), signer at `idx`.
    fn owned_input(set: &UtxoSet, amount: u64, ring_size: usize, idx: usize) -> OwnedInput {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let mut ring = Vec::new();
        for _ in 0..ring_size {
            let sk = Scalar::random(&mut OsRng);
            let bl = Scalar::random(&mut OsRng);
            let pk = sk * g;
            let c = Scalar::from(amount) * h + bl * g;
            set.record_output_key(&hexp(&pk), &hexp(&c)).unwrap();
            ring.push(RingMember {
                public_key: pk,
                commitment: c,
            });
        }
        let spend = Scalar::random(&mut OsRng);
        let blinding = Scalar::random(&mut OsRng);
        let pk = spend * g;
        let c = Scalar::from(amount) * h + blinding * g;
        set.record_output_key(&hexp(&pk), &hexp(&c)).unwrap();
        ring[idx] = RingMember {
            public_key: pk,
            commitment: c,
        };
        OwnedInput {
            spend_secret: spend,
            amount,
            blinding,
            ring,
            real_index: idx,
        }
    }

    fn recipient(amount: u64) -> ConfRecipient {
        let g = RISTRETTO_BASEPOINT_POINT;
        ConfRecipient {
            view_pub: Scalar::random(&mut OsRng) * g,
            spend_pub: Scalar::random(&mut OsRng) * g,
            amount,
        }
    }

    #[test]
    fn builds_consensus_valid_1in_1out() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inp = owned_input(&set, 100, 4, 1);
        let tx =
            build_confidential_transaction(vec![inp], vec![recipient(100)], 0, &net).unwrap();
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net, &mut seen).is_ok());
    }

    #[test]
    fn builds_valid_2in_2out() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inputs = vec![owned_input(&set, 70, 4, 0), owned_input(&set, 30, 4, 3)];
        let tx = build_confidential_transaction(inputs, vec![recipient(60), recipient(40)], 0, &net)
            .unwrap();
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net, &mut seen).is_ok());
    }

    #[test]
    fn confidential_tx_passes_mempool_validation_path() {
        // Regression for the mempool fall-through bug: a confidential tx must be
        // ACCEPTED by TxValidator::validate_tx_for_network (which previously fell
        // through into the transparent UTXO loop and rejected it).
        use crate::domain::transaction::tx_validator::TxValidator;
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inp = owned_input(&set, 100, 4, 1);
        let tx = build_confidential_transaction(vec![inp], vec![recipient(100)], 0, &net).unwrap();
        assert!(
            TxValidator::validate_tx_for_network(&tx, &set, &net),
            "confidential tx must pass the mempool validation path"
        );
    }

    #[test]
    fn builds_valid_1in_3out_with_fee() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inp = owned_input(&set, 100, 8, 5);
        let tx = build_confidential_transaction(
            vec![inp],
            vec![recipient(50), recipient(30), recipient(18)],
            2,
            &net,
        )
        .unwrap();
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net, &mut seen).is_ok());
    }

    #[test]
    fn rejects_amount_imbalance() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inp = owned_input(&set, 100, 4, 1);
        assert!(build_confidential_transaction(vec![inp], vec![recipient(90)], 0, &net).is_err());
    }

    #[test]
    fn rejects_input_opening_mismatch() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let mut inp = owned_input(&set, 100, 4, 1);
        inp.blinding += Scalar::ONE;
        assert!(build_confidential_transaction(vec![inp], vec![recipient(100)], 0, &net).is_err());
    }

    #[test]
    fn tampered_output_breaks_consensus() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let inp = owned_input(&set, 100, 4, 2);
        let mut tx =
            build_confidential_transaction(vec![inp], vec![recipient(100)], 0, &net).unwrap();
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let bad = Scalar::from(123u64) * h + Scalar::random(&mut OsRng) * g;
        tx.outputs[0].commitment = Some(hexp(&bad));
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net, &mut seen).is_err());
    }
}
