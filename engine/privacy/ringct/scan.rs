// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Recipient-side scanning + recovery of confidential outputs.

use crate::domain::address::stealth_address::{derive_hash_scalar_with_context, StealthAddress};
use crate::domain::transaction::transaction::TxOutput;
use crate::engine::privacy::confidential::pedersen::generator_h;
use crate::engine::privacy::ringct::amount_encoding;
use crate::engine::privacy::ringct::serialization::point_from_hex;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// A recovered confidential output the wallet owns.
pub struct RecoveredOutput {
    pub amount: u64,
    pub blinding: Scalar,
    pub one_time_pubkey: RistrettoPoint,
}

/// Returns `Some` iff `output` is addressed to (view_priv, spend_pub) AND its
/// commitment opens to the decrypted amount with the derived blinding. Pure;
/// no chain access.
pub fn scan_confidential_output(
    output: &TxOutput,
    output_index: u32,
    view_priv: &Scalar,
    spend_pub: &RistrettoPoint,
) -> Option<RecoveredOutput> {
    let g = RISTRETTO_BASEPOINT_POINT;
    let h = generator_h();

    let r_point = point_from_hex(output.ephemeral_pubkey.as_ref()?)?;
    let commitment = point_from_hex(output.commitment.as_ref()?)?;
    let one_time_pubkey = point_from_hex(output.one_time_pubkey.as_ref()?)?;
    let enc = amount_encoding::enc_from_hex(output.encrypted_amount.as_ref()?)?;

    // Shared secret + ownership: P' = Hs(ss)·G + S must equal the output's P.
    let ss = StealthAddress::recipient_shared_secret(&r_point, view_priv);
    // Same derivation the sender used for the one-time pubkey (no context).
    let hs = derive_hash_scalar_with_context(&ss, "", 0).ok()?;
    if (hs * g + spend_pub) != one_time_pubkey {
        return None;
    }

    // Decrypt amount + derive blinding; commitment must open to them.
    let mask = amount_encoding::amount_mask(&ss, output_index);
    let amount = amount_encoding::decrypt_amount(&enc, &mask);
    let blinding = amount_encoding::derive_blinding(&ss, output_index);
    if (Scalar::from(amount) * h + blinding * g) != commitment {
        return None;
    }

    Some(RecoveredOutput {
        amount,
        blinding,
        one_time_pubkey,
    })
}

/// Derive the one-time spend secret `x` (with `x·G == one_time_pubkey`). Needs
/// the wallet spend private key. Returns `None` if the output is malformed.
pub fn recover_spend_secret(
    output: &TxOutput,
    view_priv: &Scalar,
    spend_priv: &Scalar,
) -> Option<Scalar> {
    let r_point = point_from_hex(output.ephemeral_pubkey.as_ref()?)?;
    StealthAddress::derive_one_time_private_key(&r_point, view_priv, spend_priv).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::node::node_config::NetworkMode;
    use crate::domain::utxo::utxo_set::UtxoSet;
    use crate::engine::privacy::ringct::builder::{build_confidential_transaction, ConfRecipient, OwnedInput};
    use crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx;
    use crate::engine::privacy::ringct::dual_clsag::RingMember;
    use rand::rngs::OsRng;
    use std::collections::HashSet;

    fn keypair() -> (Scalar, RistrettoPoint) {
        let s = Scalar::random(&mut OsRng);
        (s, s * RISTRETTO_BASEPOINT_POINT)
    }

    fn hx(p: &RistrettoPoint) -> String {
        hex::encode(p.compress().as_bytes())
    }

    /// One owned input of `amount` (ring size `ring`, signer idx 0), all members
    /// recorded into `set`'s okey index.
    fn owned(set: &UtxoSet, amount: u64, ring: usize) -> OwnedInput {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let mut members = Vec::new();
        for _ in 0..ring {
            let sk = Scalar::random(&mut OsRng);
            let bl = Scalar::random(&mut OsRng);
            let pk = sk * g;
            let c = Scalar::from(amount) * h + bl * g;
            set.record_output_key(&hx(&pk), &hx(&c)).unwrap();
            members.push(RingMember { public_key: pk, commitment: c });
        }
        let spend = Scalar::random(&mut OsRng);
        let bl = Scalar::random(&mut OsRng);
        let pk = spend * g;
        let c = Scalar::from(amount) * h + bl * g;
        set.record_output_key(&hx(&pk), &hx(&c)).unwrap();
        members[0] = RingMember { public_key: pk, commitment: c };
        OwnedInput { spend_secret: spend, amount, blinding: bl, ring: members, real_index: 0 }
    }

    #[test]
    fn scan_recovers_amount_and_spend_key() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();

        let (view_priv, view_pub) = keypair();
        let (spend_priv, spend_pub) = keypair();

        let tx = build_confidential_transaction(
            vec![owned(&set, 100, 2)],
            vec![ConfRecipient { view_pub, spend_pub, amount: 100 }],
            0,
            &net,
        )
        .unwrap();

        let rec = scan_confidential_output(&tx.outputs[0], 0, &view_priv, &spend_pub)
            .expect("should own this output");
        assert_eq!(rec.amount, 100);
        assert_eq!(
            Scalar::from(100u64) * h + rec.blinding * g,
            point_from_hex(tx.outputs[0].commitment.as_ref().unwrap()).unwrap()
        );

        let x = recover_spend_secret(&tx.outputs[0], &view_priv, &spend_priv).unwrap();
        assert_eq!(x * g, rec.one_time_pubkey);

        // Not owned by a different recipient.
        let (other_v, _) = keypair();
        assert!(scan_confidential_output(&tx.outputs[0], 0, &other_v, &spend_pub).is_none());

        // Tampered encrypted_amount → decrypted amount no longer opens commitment.
        let mut bad = tx.outputs[0].clone();
        bad.encrypted_amount = Some("ffffffffffffffff".into());
        assert!(scan_confidential_output(&bad, 0, &view_priv, &spend_pub).is_none());
    }

    #[test]
    fn round_trip_build_scan_recover_spend_verify() {
        let set = UtxoSet::new_empty();
        let net = NetworkMode::Mainnet;
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();

        // A pays B 100.
        let (b_view_priv, b_view_pub) = keypair();
        let (b_spend_priv, b_spend_pub) = keypair();
        let tx1 = build_confidential_transaction(
            vec![owned(&set, 100, 4)],
            vec![ConfRecipient { view_pub: b_view_pub, spend_pub: b_spend_pub, amount: 100 }],
            0,
            &net,
        )
        .unwrap();
        let mut seen = HashSet::new();
        assert!(verify_confidential_tx(&tx1, &set, &net, &mut seen).is_ok());

        // tx1's output is now a real on-chain confidential output.
        let out = &tx1.outputs[0];
        set.record_output_key(out.one_time_pubkey.as_ref().unwrap(), out.commitment.as_ref().unwrap())
            .unwrap();

        // B scans + recovers.
        let rec = scan_confidential_output(out, 0, &b_view_priv, &b_spend_pub).expect("B owns it");
        assert_eq!(rec.amount, 100);
        let x = recover_spend_secret(out, &b_view_priv, &b_spend_priv).unwrap();

        // B builds a spend of 100 to C, using the recovered output as the real
        // ring member (plus fresh decoys, all recorded). >=4 total for the
        // consensus ring-size floor.
        let mut bring = Vec::new();
        for _ in 0..3 {
            let sk = Scalar::random(&mut OsRng);
            let bl = Scalar::random(&mut OsRng);
            let pk = sk * g;
            let c = Scalar::from(100u64) * h + bl * g;
            set.record_output_key(&hx(&pk), &hx(&c)).unwrap();
            bring.push(RingMember { public_key: pk, commitment: c });
        }
        bring.push(RingMember {
            public_key: rec.one_time_pubkey,
            commitment: point_from_hex(out.commitment.as_ref().unwrap()).unwrap(),
        });
        let real_idx = bring.len() - 1;
        let b_owned = OwnedInput {
            spend_secret: x,
            amount: rec.amount,
            blinding: rec.blinding,
            ring: bring,
            real_index: real_idx,
        };
        let (_c_view_priv, c_view_pub) = keypair();
        let (_c_spend_priv, c_spend_pub) = keypair();
        let tx2 = build_confidential_transaction(
            vec![b_owned],
            vec![ConfRecipient { view_pub: c_view_pub, spend_pub: c_spend_pub, amount: 100 }],
            0,
            &net,
        )
        .unwrap();
        let mut seen2 = HashSet::new();
        assert!(
            verify_confidential_tx(&tx2, &set, &net, &mut seen2).is_ok(),
            "B's recovered output must be spendable and consensus-valid"
        );
    }
}
