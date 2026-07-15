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
use crate::domain::transaction::tx_validator::TxValidator;
use crate::domain::utxo::utxo_set::{utxo_key, UtxoSet};
use crate::engine::privacy::confidential::pedersen::RealPedersenCommitment;
use curve25519_dalek::scalar::Scalar;
use crate::engine::privacy::confidential::range_proof;
use crate::engine::privacy::ringct::dual_clsag;
use crate::engine::privacy::ringct::ring_signature::{MAX_RING_SIZE, MIN_RING_SIZE};
use crate::engine::privacy::ringct::serialization::point_from_hex;
use crate::engine::privacy::ringct::tx_confidential::{
    parse_confidential_input, parse_confidential_output,
};
use crate::errors::StorageError;
use std::collections::HashSet;

fn err(msg: String) -> StorageError {
    StorageError::Other(msg)
}

/// Parse a canonical 32-byte Ristretto scalar from hex.
fn scalar_from_hex(h: &str) -> Option<Scalar> {
    let bytes = hex::decode(h).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
}

/// Verify a SHIELD transaction: TRANSPARENT inputs -> CONFIDENTIAL outputs.
///
/// The entry point into the RingCT pool. Each transparent input's PUBLIC amount
/// `A_i` is read from the UTXO SET (never the tx) and turned into the input
/// pseudo-commitment `C_in = A_i·H + r_i·G` (ShadowDAG convention: amount on H,
/// blinding on G — see pedersen.rs). The blinding `r_i` (the tx's
/// `shield_blinding`) is the ONLY input-side value the tx supplies; it cannot
/// move value once `A_i` is chain-fixed, only balance the output blindings.
/// Outputs are confidential (amount==0 + range proof). The existing homomorphic
/// balance `Σ C_in == Σ C_out + fee·H` then forces `Σ A_i = Σ a_j + fee`.
///
/// PURE: reads the UTXO set, no mutation. Double-spend of the transparent inputs
/// (mark-spent) is enforced on the APPLY path, not here. SECURITY: consensus-
/// critical / inflation-risk — external cryptographic review required before
/// mainnet. See docs/superpowers/specs/2026-07-04-shield-tx-design.md.
pub fn verify_shield_tx(
    tx: &Transaction,
    utxo_set: &UtxoSet,
    network: &NetworkMode,
) -> Result<(), StorageError> {
    if tx.inputs.is_empty() || tx.outputs.is_empty() {
        return Err(err(format!("shield tx {} empty inputs/outputs", tx.hash)));
    }

    // Transparent inputs are PUBLIC spends — Ed25519 ownership, NOT ring/CLSAG.
    if !TxValidator::verify_signatures_for_network(tx, network) {
        return Err(err(format!("shield tx {}: invalid input signature(s)", tx.hash)));
    }
    let signing_msg = TxHash::signing_message_for_network(tx, network);

    // ── Inputs: reconstruct C_in = A_i·H + r_i·G from the CHAIN amount ──
    let mut input_commitments = Vec::with_capacity(tx.inputs.len());
    let mut sum_in: u64 = 0;
    let mut seen_outpoints: HashSet<String> = HashSet::new();
    for input in &tx.inputs {
        // Type separation (inflation V3): a shield input must NOT carry any
        // ring/confidential field — it is a plain transparent spend.
        if input.key_image.is_some()
            || input.ring_members.is_some()
            || input.ring_signature.is_some()
            || input.ring_commitments.is_some()
            || input.pseudo_commitment.is_some()
        {
            return Err(err(format!(
                "shield tx {}: input carries confidential/ring fields (must be transparent)",
                tx.hash
            )));
        }

        // Reject duplicate outpoints within the tx (anti self/double-count).
        if !seen_outpoints.insert(format!("{}:{}", input.txid, input.index)) {
            return Err(err(format!("shield tx {}: duplicate input outpoint", tx.hash)));
        }

        // Authoritative amount from the UTXO SET — NEVER from the tx (inflation V2).
        let key = utxo_key(&input.txid, input.index)
            .map_err(|e| err(format!("shield tx {}: bad outpoint: {}", tx.hash, e)))?;
        let utxo = utxo_set
            .get_utxo(&key)
            .ok_or_else(|| err(format!("shield tx {}: input {} not found", tx.hash, key)))?;
        if utxo.spent {
            return Err(err(format!("shield tx {}: input {} already spent", tx.hash, key)));
        }
        if !TxValidator::verify_input_ownership_by_address(input, &utxo.address, &signing_msg) {
            return Err(err(format!(
                "shield tx {}: input {} ownership mismatch",
                tx.hash, key
            )));
        }

        // r_i — the ONLY input-side value the tx supplies (a blinding, not value).
        let r_i = scalar_from_hex(input.shield_blinding.as_deref().unwrap_or("")).ok_or_else(|| {
            err(format!("shield tx {}: missing/invalid shield_blinding", tx.hash))
        })?;

        // C_in = A_i·H + r_i·G via the shared commit primitive (inflation V1:
        // amount on H, NEVER A_i·G).
        input_commitments.push(RealPedersenCommitment::commit(utxo.amount, r_i).commitment);
        sum_in = sum_in
            .checked_add(utxo.amount)
            .ok_or_else(|| err(format!("shield tx {}: input amount overflow", tx.hash)))?;
    }

    // ── Outputs: confidential (amount==0 + range proof) ──
    let mut output_commitments = Vec::with_capacity(tx.outputs.len());
    let mut seen_otk: HashSet<&str> = HashSet::new();
    for output in &tx.outputs {
        if output.amount != 0 {
            return Err(err(format!(
                "shield tx {}: confidential output amount must be 0 (value hidden in commitment)",
                tx.hash
            )));
        }
        // OTK freshness (mirrors the key-image uniqueness guard): a confidential
        // output's one-time pubkey MUST be globally fresh. Without this, a tx can
        // reuse an existing on-chain okey; apply then overwrites okey->commitment
        // (making the earlier output uncitable as a ring member) and a reorg
        // rollback deletes the victim's still-live entry, desyncing okeyidx.
        if let Some(otk) = output.one_time_pubkey.as_deref() {
            if utxo_set.output_key_exists(otk) {
                return Err(err(format!(
                    "shield tx {}: output one-time key already exists on-chain",
                    tx.hash
                )));
            }
            if !seen_otk.insert(otk) {
                return Err(err(format!(
                    "shield tx {}: duplicate output one-time key within tx",
                    tx.hash
                )));
            }
        }
        let view = parse_confidential_output(output)
            .ok_or_else(|| err(format!("shield tx {}: malformed confidential output", tx.hash)))?;
        if !range_proof::verify(&view.commitment, &view.range_proof) {
            return Err(err(format!("shield tx {}: range proof failed", tx.hash)));
        }
        output_commitments.push(view.commitment);
    }

    // Fee is public and on H; must not exceed the public input total (inflation V5).
    if tx.fee > sum_in {
        return Err(err(format!(
            "shield tx {}: fee {} exceeds input sum {}",
            tx.hash, tx.fee, sum_in
        )));
    }

    // ── Homomorphic balance: Σ C_in == Σ C_out + fee·H ──
    if !RealPedersenCommitment::verify_balance(&input_commitments, &output_commitments, tx.fee) {
        return Err(err(format!(
            "shield tx {}: commitments do not balance",
            tx.hash
        )));
    }

    Ok(())
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
        // Strict type separation (spec §4.5): a confidential (ring) input must
        // NOT carry the shield-only blinding scalar. It is inert on this path
        // (value comes from the ring/pseudo-commitment, not shield_blinding), but
        // an ambiguous tx shape is rejected so the two input worlds never blur.
        if input.shield_blinding.is_some() {
            return Err(err(format!(
                "confidential tx {}: ring input must not carry shield_blinding",
                tx.hash
            )));
        }
        let view = parse_confidential_input(input)
            .ok_or_else(|| err(format!("confidential tx {}: malformed input", tx.hash)))?;

        // Every ring member must be a real on-chain output with the authentic
        // commitment (binds P AND C). `ring_members` is present because the
        // parse succeeded.
        let members = input
            .ring_members
            .as_ref()
            .ok_or_else(|| err(format!("confidential tx {}: missing ring_members", tx.hash)))?;

        // Minimum ring size is the anonymity-set floor and MUST be enforced in
        // THIS shared gate — it is the only check run on the mempool, block-UTXO,
        // and reorg/apply paths (RingValidator's size check only runs on the
        // block-body structural layer). Without it a ring of size 1 verifies
        // cryptographically and gets gossiped, revealing exactly which output was
        // spent (full deanonymization). Bound above too, to cap DoS.
        if members.len() < MIN_RING_SIZE || members.len() > MAX_RING_SIZE {
            return Err(err(format!(
                "confidential tx {}: ring size {} out of bounds [{}, {}]",
                tx.hash,
                members.len(),
                MIN_RING_SIZE,
                MAX_RING_SIZE
            )));
        }

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

        // Bind the ADVERTISED key image (TxInput.key_image — the exact field the
        // apply layer records into the spent-key-image set) to the VERIFIED key
        // image embedded in the dual-CLSAG signature (which is what the uniqueness
        // check below and CLSAG linkability actually enforce). Without this they
        // are two independent sources of truth: an owner could advertise K1 while
        // the signature carries I, pass the "I unspent" check, have apply record
        // K1, then spend the SAME output again with a fresh advertised K2 (I still
        // looks unspent) — a cross-block confidential double-spend. Canonical
        // Ristretto decode also rejects a non-canonical advertised encoding, and a
        // missing field is rejected outright.
        let advertised_hex = input
            .key_image
            .as_deref()
            .ok_or_else(|| err(format!("confidential tx {}: missing key image", tx.hash)))?;
        let advertised = point_from_hex(advertised_hex)
            .ok_or_else(|| err(format!("confidential tx {}: malformed key image", tx.hash)))?;
        if advertised != view.key_image {
            return Err(err(format!(
                "confidential tx {}: advertised key image does not match the signature",
                tx.hash
            )));
        }
        // Uniqueness key = canonical lowercase encoding of the verified key image.
        let ki_hex = hex::encode(view.key_image.compress().as_bytes());
        // Require the ADVERTISED encoding to be EXACTLY this canonical lowercase
        // form. hex::decode (via point_from_hex) accepts both cases, so "ABCD.."
        // and "abcd.." decode to the same point and pass the equality above — but
        // the apply layer records the RAW input.key_image string, so a spend
        // advertising uppercase is stored under "ki:ABCD.." while the uniqueness
        // check looks up "ki:abcd..": the same output could then be spent again
        // advertising lowercase (cross-block double-spend). Rejecting any
        // non-canonical encoding makes the recorded string byte-identical to the
        // checked key. (External audit re-open of P0-A: hex case-aliasing.)
        if advertised_hex != ki_hex {
            return Err(err(format!(
                "confidential tx {}: key image must be canonical lowercase hex",
                tx.hash
            )));
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
    let mut seen_otk: HashSet<&str> = HashSet::new();
    for output in &tx.outputs {
        // PRIVACY INVARIANT: a confidential output's value lives ONLY in its
        // Pedersen commitment. The plaintext `amount` field MUST be 0 — otherwise
        // a sender could publish the true value in the clear (and downstream
        // scanners trust it), defeating amount-hiding. Enforced in the shared
        // gate so it holds identically on mempool, block, and reorg/apply paths.
        if output.amount != 0 {
            return Err(err(format!(
                "confidential tx {}: plaintext output amount must be 0 (value is hidden in the commitment)",
                tx.hash
            )));
        }
        // OTK freshness (mirrors the key-image uniqueness guard): the output's
        // one-time pubkey MUST be globally fresh. Reusing an existing on-chain
        // okey lets apply overwrite okey->commitment and a reorg rollback delete
        // the victim's entry (uncitable ring member + okeyidx desync).
        if let Some(otk) = output.one_time_pubkey.as_deref() {
            if utxo_set.output_key_exists(otk) {
                return Err(err(format!(
                    "confidential tx {}: output one-time key already exists on-chain",
                    tx.hash
                )));
            }
            if !seen_otk.insert(otk) {
                return Err(err(format!(
                    "confidential tx {}: duplicate output one-time key within tx",
                    tx.hash
                )));
            }
        }
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
                shield_blinding: None,
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
    fn rejects_advertised_key_image_not_matching_signature() {
        // CRITICAL (P0-A): the double-spend set is keyed on TxInput.key_image at
        // apply time, but uniqueness + CLSAG linkability bind the key image
        // EMBEDDED in the signature. If they can differ, an owner advertises K1,
        // apply records K1, and a second spend with the same signature (image I)
        // plus a fresh advertised K2 is not detected as a double-spend. The gate
        // must reject any advertised KI that does not equal the signature's KI,
        // and reject a missing one.
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        tx.inputs[0].key_image =
            Some(hexp(&(Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT)));
        let mut seen = HashSet::new();
        assert!(
            verify_confidential_tx(&tx, &set, &net(), &mut seen).is_err(),
            "advertised key image != signature key image must be rejected"
        );

        let set2 = UtxoSet::new_empty();
        let mut tx2 = valid_conf_tx(&set2, 100);
        tx2.inputs[0].key_image = None;
        let mut seen2 = HashSet::new();
        assert!(
            verify_confidential_tx(&tx2, &set2, &net(), &mut seen2).is_err(),
            "missing advertised key image must be rejected"
        );

        // Hex CASE-ALIASING: the VALID key image, but uppercased. It decodes to
        // the exact same point (passing point-equality) yet is not the canonical
        // lowercase encoding the apply layer / uniqueness set key on — must reject,
        // else the same output double-spends via "ki:ABCD.." vs "ki:abcd..".
        let set3 = UtxoSet::new_empty();
        let mut tx3 = valid_conf_tx(&set3, 100);
        let canonical_ki = tx3.inputs[0].key_image.clone().unwrap();
        assert_eq!(canonical_ki, canonical_ki.to_lowercase(), "baseline KI is lowercase");
        tx3.inputs[0].key_image = Some(canonical_ki.to_uppercase());
        let mut seen3 = HashSet::new();
        assert!(
            verify_confidential_tx(&tx3, &set3, &net(), &mut seen3).is_err(),
            "uppercase (non-canonical) key image must be rejected (case-aliasing double-spend)"
        );
    }

    #[test]
    fn confidential_send_skips_sig_gate_and_clsag_gate_is_authority() {
        // Regression for the RingCT block-enforcement fix: a confidential send has
        // ring-signed inputs (empty Ed25519 signature/pub_key), so it must SKIP the
        // transparent signature gate (`verify_signatures_for_network`) and be gated
        // solely by the dual-key CLSAG gate. A forged tx still skips the sig gate
        // but is rejected by the CLSAG gate — proving where the real authority lies.
        use crate::domain::transaction::tx_validator::TxValidator;

        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100);

        assert!(
            TxValidator::verify_signatures_for_network(&tx, &net()),
            "confidential send must pass (skip) the transparent Ed25519 signature gate"
        );
        let mut seen = HashSet::new();
        assert!(
            verify_confidential_tx(&tx, &set, &net(), &mut seen).is_ok(),
            "valid confidential send must pass the CLSAG consensus gate"
        );

        // Forge the hidden output value. The sig gate still skips it (still
        // confidential), but the CLSAG gate rejects it.
        let mut forged = tx.clone();
        let bogus = Scalar::from(101u64) * generator_h()
            + Scalar::random(&mut OsRng) * RISTRETTO_BASEPOINT_POINT;
        forged.outputs[0].commitment = Some(hexp(&bogus));
        assert!(
            TxValidator::verify_signatures_for_network(&forged, &net()),
            "forged confidential tx still skips the sig gate (CLSAG is the authority)"
        );
        let mut seen2 = HashSet::new();
        assert!(
            verify_confidential_tx(&forged, &set, &net(), &mut seen2).is_err(),
            "forged confidential tx must be rejected by the CLSAG consensus gate"
        );
    }

    // ── Shield tests (transparent -> confidential) ──────────────────────────

    /// Build a valid 1-in/1-out shield tx: a transparent UTXO of `amt` owned by
    /// a fresh keypair is seeded into `set` (via a coinbase apply), then shielded
    /// into one confidential output of `amt - fee`.
    fn valid_shield_tx(set: &UtxoSet, amt: u64, fee: u64) -> Transaction {
        valid_shield_tx_with_key(set, amt, fee).0
    }

    /// Ed25519-sign every input of a shield tx over its (current) transparent
    /// signing message. Call AFTER any mutation to fields committed by
    /// `canonical_bytes` (fee, outputs, inputs) so the signature stays valid and
    /// the SPECIFIC consensus rule — not tamper detection — is what rejects it.
    fn resign_shield(tx: &mut Transaction, sk: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let msg = TxHash::signing_message_for_network(tx, &net());
        let sig = sk.sign(&msg);
        for inp in tx.inputs.iter_mut() {
            inp.signature = hex::encode(sig.to_bytes());
        }
    }

    /// Same as `valid_shield_tx`, also returning the input's signing key so a
    /// test can craft a malicious variant and re-sign it (via `resign_shield`).
    fn valid_shield_tx_with_key(
        set: &UtxoSet,
        amt: u64,
        fee: u64,
    ) -> (Transaction, ed25519_dalek::SigningKey) {
        use crate::domain::transaction::transaction::Transaction as Tx;
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};

        // Keypair + mainnet address = SD1 + sha256("ShadowDAG_Addr_v1"||pk)[..20].
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let pk_hex = hex::encode(pk.to_bytes());
        let mut ah = Sha256::new();
        ah.update(b"ShadowDAG_Addr_v1");
        ah.update(pk.to_bytes());
        let address = format!("SD1{}", hex::encode(&ah.finalize()[..20]));

        // Seed a transparent UTXO owned by `address` via a coinbase apply.
        let cb_hash = "a".repeat(64);
        let mut cb = Tx::new_coinbase(cb_hash.clone(), vec![TxOutput::new(address.clone(), amt)], 0, 1);
        cb.hash = cb_hash.clone();
        set.apply_block_dag_ordered(std::slice::from_ref(&cb), 0, &"b".repeat(64))
            .unwrap();

        // One confidential output of value (amt - fee). Balance (1-in/1-out):
        // C_in = amt·H + r_i·G, C_out = (amt-fee)·H + r_out·G, plus fee·H ⇒ r_i = r_out.
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let out_val = amt - fee;
        let r_out = Scalar::random(&mut OsRng);
        let r_i = r_out; // makes the blindings balance
        let out_commit = Scalar::from(out_val) * h + r_out * g;
        let proof = prove(out_val, &r_out);
        let one_time = Scalar::random(&mut OsRng) * g;
        let eph = Scalar::random(&mut OsRng) * g;

        let mut tx = Transaction {
            hash: "5".repeat(64),
            inputs: vec![TxInput {
                txid: cb_hash,
                index: 0,
                owner: address,
                signature: String::new(),
                pub_key: pk_hex.clone(),
                key_image: None,
                ring_members: None,
                ring_signature: None,
                ring_commitments: None,
                pseudo_commitment: None,
                shield_blinding: Some(hex::encode(r_i.to_bytes())),
            }],
            outputs: vec![TxOutput {
                address: "SD1p".into(),
                amount: 0,
                commitment: Some(hexp(&out_commit)),
                range_proof: Some(range_proof_to_hex(&proof)),
                ephemeral_pubkey: Some(hexp(&eph)),
                one_time_pubkey: Some(hexp(&one_time)),
                encrypted_amount: None,
            }],
            fee,
            timestamp: 1_735_689_600_000,
            is_coinbase: false,
            tx_type: TxType::Shield,
            payload_hash: None,
            ..Default::default()
        };
        // Ed25519 sign the transparent-ownership message.
        let msg = TxHash::signing_message_for_network(&tx, &net());
        let sig = sk.sign(&msg);
        tx.inputs[0].signature = hex::encode(sig.to_bytes());
        (tx, sk)
    }

    #[test]
    fn accepts_valid_shield_tx() {
        let set = UtxoSet::new_empty();
        let tx = valid_shield_tx(&set, 1_000, 10);
        assert!(
            verify_shield_tx(&tx, &set, &net()).is_ok(),
            "a balanced shield tx must verify"
        );
    }

    #[test]
    fn shield_rejects_inflated_output() {
        // INFLATION: an output committing to MORE than the input value must fail
        // balance. The input amount A is chain-fixed (read from the UTXO set), so
        // the attacker cannot make Σ outputs exceed Σ A - fee.
        let set = UtxoSet::new_empty();
        let mut tx = valid_shield_tx(&set, 1_000, 10);
        assert!(verify_shield_tx(&tx, &set, &net()).is_ok());
        // Re-commit the output to 1_000_000 (mint) with a fresh blinding.
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let r = Scalar::random(&mut OsRng);
        let fat = Scalar::from(1_000_000u64) * h + r * g;
        tx.outputs[0].commitment = Some(hexp(&fat));
        tx.outputs[0].range_proof = Some(range_proof_to_hex(&prove(1_000_000, &r)));
        assert!(
            verify_shield_tx(&tx, &set, &net()).is_err(),
            "an inflated output (value > input) must be rejected by the balance"
        );
    }

    #[test]
    fn shield_rejects_confidential_input_fields() {
        // TYPE SEPARATION: a shield input must not carry ring/confidential fields.
        let set = UtxoSet::new_empty();
        let mut tx = valid_shield_tx(&set, 1_000, 10);
        tx.inputs[0].key_image = Some("00".repeat(32));
        assert!(
            verify_shield_tx(&tx, &set, &net()).is_err(),
            "a shield input carrying a key image must be rejected"
        );
    }

    #[test]
    fn shield_rejects_duplicate_input_outpoint() {
        // DOUBLE-COUNT (V4): the same transparent outpoint listed twice in one
        // shield would count its value twice. Duplicate the (signed) input, then
        // re-sign the 2-input tx so the duplicate-outpoint rule — not a stale
        // signature — is what rejects it.
        let set = UtxoSet::new_empty();
        let (mut tx, sk) = valid_shield_tx_with_key(&set, 1_000, 10);
        let dup = tx.inputs[0].clone();
        tx.inputs.push(dup);
        resign_shield(&mut tx, &sk);
        let e = verify_shield_tx(&tx, &set, &net()).unwrap_err().to_string();
        assert!(e.contains("duplicate input outpoint"), "must reject on duplicate outpoint, got: {}", e);
    }

    #[test]
    fn shield_rejects_fee_exceeding_input_sum() {
        // INFLATION (V5): fee is public and paid to the coinbase; a fee larger
        // than the shielded input total would let the miner mint the difference.
        let set = UtxoSet::new_empty();
        let (mut tx, sk) = valid_shield_tx_with_key(&set, 1_000, 10);
        tx.fee = 5_000; // > sum_in (1_000)
        resign_shield(&mut tx, &sk);
        let e = verify_shield_tx(&tx, &set, &net()).unwrap_err().to_string();
        assert!(e.contains("exceeds input sum"), "must reject fee > Σ inputs, got: {}", e);
    }

    #[test]
    fn shield_rejects_nonzero_plaintext_output_amount() {
        // PRIVACY (V6): a shield output is confidential — its plaintext `amount`
        // must be 0 (value lives in the commitment). A nonzero amount both leaks
        // the value AND (on transparent-summing paths) could be double-counted.
        let set = UtxoSet::new_empty();
        let (mut tx, sk) = valid_shield_tx_with_key(&set, 1_000, 10);
        tx.outputs[0].amount = 990; // leak the value in the clear
        resign_shield(&mut tx, &sk);
        let e = verify_shield_tx(&tx, &set, &net()).unwrap_err().to_string();
        assert!(e.contains("amount must be 0"), "must reject nonzero output amount, got: {}", e);
    }

    #[test]
    fn shield_rejects_reused_output_key() {
        // OTK FRESHNESS: a shield output whose one_time_pubkey already exists on
        // chain must be rejected — else apply overwrites the prior okey and a
        // reorg rollback deletes the victim's still-live confidential output.
        let set = UtxoSet::new_empty();
        let tx = valid_shield_tx(&set, 1_000, 10);
        assert!(verify_shield_tx(&tx, &set, &net()).is_ok(), "sanity: fresh OTK verifies");
        // Pre-record the output's OTK as if a prior block already used it.
        let otk = tx.outputs[0].one_time_pubkey.clone().unwrap();
        set.record_output_key(&otk, &"ff".repeat(32)).unwrap();
        let e = verify_shield_tx(&tx, &set, &net()).unwrap_err().to_string();
        assert!(
            e.contains("one-time key already exists"),
            "must reject reused OTK, got: {}",
            e
        );
    }

    #[test]
    fn confidential_rejects_reused_output_key() {
        // OTK FRESHNESS on the ring path: the output one-time pubkey must be
        // fresh, mirroring the key-image uniqueness guard.
        let set = UtxoSet::new_empty();
        let tx = valid_conf_tx(&set, 100);
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_ok());
        // Pre-record the output's OTK; a NEW verification (fresh seen set) must
        // now reject on OTK reuse before the balance check.
        let otk = tx.outputs[0].one_time_pubkey.clone().unwrap();
        set.record_output_key(&otk, &"ff".repeat(32)).unwrap();
        let mut seen2 = HashSet::new();
        let e = verify_confidential_tx(&tx, &set, &net(), &mut seen2)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("one-time key already exists"),
            "must reject reused OTK, got: {}",
            e
        );
    }

    #[test]
    fn confidential_rejects_input_carrying_shield_blinding() {
        // TYPE SEPARATION (V3, reverse): a ring input must NOT carry the
        // shield-only blinding scalar — an ambiguous input shape is rejected.
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        tx.inputs[0].shield_blinding = Some("00".repeat(32));
        let mut seen = HashSet::new();
        let e = verify_confidential_tx(&tx, &set, &net(), &mut seen)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("must not carry shield_blinding"),
            "ring input with shield_blinding must be rejected, got: {}",
            e
        );
    }

    #[test]
    fn rejects_nonzero_plaintext_output_amount() {
        // Privacy invariant: a confidential output must carry plaintext amount 0
        // (value hidden in the commitment). A nonzero amount would leak the value.
        let set = UtxoSet::new_empty();
        let mut tx = valid_conf_tx(&set, 100);
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx, &set, &net(), &mut seen).is_ok());
        tx.outputs[0].amount = 100; // leak the real value in the clear
        let mut seen2 = HashSet::new();
        assert!(
            verify_confidential_tx(&tx, &set, &net(), &mut seen2).is_err(),
            "nonzero plaintext amount on a confidential output must be rejected"
        );
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
    fn rejects_ring_below_min_size() {
        // A CRYPTOGRAPHICALLY VALID confidential tx with a ring of size 1 must be
        // rejected by the shared gate: a size-1 ring has zero anonymity (the sole
        // member reveals the spent output). Before the floor was added here, this
        // tx passed the mempool/UTXO paths. Money invariants are irrelevant — this
        // is a privacy floor.
        let set = UtxoSet::new_empty();
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let amt = 100u64;
        let spend = Scalar::random(&mut OsRng);
        let r_in = Scalar::random(&mut OsRng);
        let pk = spend * g;
        let c_in = Scalar::from(amt) * h + r_in * g;
        set.record_output_key(&hexp(&pk), &hexp(&c_in)).unwrap();
        let ring = vec![RingMember {
            public_key: pk,
            commitment: c_in,
        }];
        let r_prime = Scalar::random(&mut OsRng);
        let pseudo = Scalar::from(amt) * h + r_prime * g;
        let z = r_in - r_prime;
        let out_commit = Scalar::from(amt) * h + r_prime * g;
        let proof = prove(amt, &r_prime);
        let mut tx = Transaction {
            hash: "d".repeat(64),
            inputs: vec![TxInput {
                txid: "0".repeat(64),
                index: 0,
                owner: String::new(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: Some(vec![hexp(&pk)]),
                ring_signature: None,
                ring_commitments: Some(vec![hexp(&c_in)]),
                pseudo_commitment: Some(hexp(&pseudo)),
                shield_blinding: None,
            }],
            outputs: vec![TxOutput {
                address: "SD1s".into(),
                amount: 0,
                commitment: Some(hexp(&out_commit)),
                range_proof: Some(range_proof_to_hex(&proof)),
                ephemeral_pubkey: Some(hexp(&(Scalar::random(&mut OsRng) * g))),
                one_time_pubkey: Some(hexp(&(Scalar::random(&mut OsRng) * g))),
                encrypted_amount: None,
            }],
            fee: 0,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type: TxType::Confidential,
            payload_hash: None,
            ..Default::default()
        };
        let ki = dual_clsag::key_image(&spend, &pk);
        tx.inputs[0].key_image = Some(hexp(&ki));
        let msg = TxHash::confidential_signing_message_for_network(&tx, &net());
        let sig = dual_clsag::sign(&msg, &ring, &pseudo, 0, &spend, &z).unwrap();
        tx.inputs[0].ring_signature = Some(dual_clsag::to_hex(&sig));

        // The CLSAG is valid, but the ring-size floor rejects it.
        let mut seen = HashSet::new();
        let res = verify_confidential_tx(&tx, &set, &net(), &mut seen);
        assert!(res.is_err(), "size-1 ring must be rejected by the shared gate");
        assert!(
            res.unwrap_err().to_string().contains("ring size"),
            "rejection must be on the ring-size floor"
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
