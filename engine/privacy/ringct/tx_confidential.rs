// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Typed, validated views of a confidential transaction's input/output fields.
//! Pure decoders: they turn the hex fields into curve types and reject anything
//! malformed. NO chain state and NO cryptographic verification (sub-project 3).

use crate::domain::transaction::transaction::{TxInput, TxOutput};
use crate::engine::privacy::confidential::range_proof::RangeProof;
use crate::engine::privacy::ringct::dual_clsag::{self, DualCLSAGSignature, RingMember};
use crate::engine::privacy::ringct::serialization::{point_from_hex, range_proof_from_hex};
use curve25519_dalek::ristretto::RistrettoPoint;

/// Validated view of a confidential input.
pub struct ConfidentialInputView {
    pub ring: Vec<RingMember>,
    pub pseudo_out: RistrettoPoint,
    pub signature: DualCLSAGSignature,
    pub key_image: RistrettoPoint,
}

/// Validated view of a confidential output.
pub struct ConfidentialOutputView {
    pub commitment: RistrettoPoint,
    pub one_time_pubkey: RistrettoPoint,
    pub ephemeral_pubkey: RistrettoPoint,
    pub range_proof: RangeProof,
}

/// Decode + validate a confidential input. `None` if any field is missing, the
/// ring/commitment/response lengths disagree, or any point/scalar is malformed.
pub fn parse_confidential_input(input: &TxInput) -> Option<ConfidentialInputView> {
    let members = input.ring_members.as_ref()?;
    let commits = input.ring_commitments.as_ref()?;
    if members.is_empty() || members.len() != commits.len() {
        return None;
    }
    let mut ring = Vec::with_capacity(members.len());
    for (p_hex, c_hex) in members.iter().zip(commits.iter()) {
        ring.push(RingMember {
            public_key: point_from_hex(p_hex)?,
            commitment: point_from_hex(c_hex)?,
        });
    }
    let pseudo_out = point_from_hex(input.pseudo_commitment.as_ref()?)?;
    let signature = dual_clsag::from_hex(input.ring_signature.as_ref()?)?;
    if signature.s.len() != ring.len() {
        return None;
    }
    let key_image = signature.key_image.decompress()?;
    Some(ConfidentialInputView {
        ring,
        pseudo_out,
        signature,
        key_image,
    })
}

/// Decode + validate a confidential output. `None` on missing/malformed fields.
pub fn parse_confidential_output(output: &TxOutput) -> Option<ConfidentialOutputView> {
    let commitment = point_from_hex(output.commitment.as_ref()?)?;
    let one_time_pubkey = point_from_hex(output.one_time_pubkey.as_ref()?)?;
    let ephemeral_pubkey = point_from_hex(output.ephemeral_pubkey.as_ref()?)?;
    let range_proof = range_proof_from_hex(output.range_proof.as_ref()?)?;
    Some(ConfidentialOutputView {
        commitment,
        one_time_pubkey,
        ephemeral_pubkey,
        range_proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::privacy::confidential::pedersen::generator_h;
    use crate::engine::privacy::confidential::range_proof::prove;
    use crate::engine::privacy::ringct::serialization::range_proof_to_hex;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    fn hexp(p: &RistrettoPoint) -> String {
        hex::encode(p.compress().as_bytes())
    }

    fn make_conf_input() -> (TxInput, Vec<RingMember>, RistrettoPoint) {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let n = 4usize;
        let idx = 1usize;
        let mut ring = Vec::new();
        for _ in 0..n {
            let sk = Scalar::random(&mut OsRng);
            let bl = Scalar::random(&mut OsRng);
            ring.push(RingMember {
                public_key: sk * g,
                commitment: Scalar::from(7u64) * h + bl * g,
            });
        }
        let spend = Scalar::random(&mut OsRng);
        let r_pi = Scalar::random(&mut OsRng);
        ring[idx].public_key = spend * g;
        ring[idx].commitment = Scalar::from(7u64) * h + r_pi * g;
        let r_prime = Scalar::random(&mut OsRng);
        let pseudo = Scalar::from(7u64) * h + r_prime * g;
        let z = r_pi - r_prime;
        let sig = dual_clsag::sign(b"m", &ring, &pseudo, idx, &spend, &z).unwrap();

        let input = TxInput {
            txid: "0".repeat(64),
            index: 0,
            owner: String::new(),
            signature: String::new(),
            pub_key: String::new(),
            key_image: Some(hex::encode(sig.key_image.as_bytes())),
            ring_members: Some(ring.iter().map(|m| hexp(&m.public_key)).collect()),
            ring_signature: Some(dual_clsag::to_hex(&sig)),
            ring_commitments: Some(ring.iter().map(|m| hexp(&m.commitment)).collect()),
            pseudo_commitment: Some(hexp(&pseudo)),
            shield_blinding: None,
        };
        (input, ring, pseudo)
    }

    #[test]
    fn parse_input_happy_path() {
        let (input, ring, pseudo) = make_conf_input();
        let view = parse_confidential_input(&input).expect("parse");
        assert_eq!(view.ring.len(), ring.len());
        assert_eq!(view.ring[0].public_key, ring[0].public_key);
        assert_eq!(view.ring[2].commitment, ring[2].commitment);
        assert_eq!(view.pseudo_out, pseudo);
    }

    #[test]
    fn parse_input_rejects_length_mismatch_and_garbage() {
        let (mut input, _, _) = make_conf_input();
        let mut rc = input.ring_commitments.clone().unwrap();
        rc.pop();
        input.ring_commitments = Some(rc);
        assert!(parse_confidential_input(&input).is_none());

        let (mut input2, _, _) = make_conf_input();
        // 0xFF*32 is a non-canonical (top-bit-set) encoding → not a valid point.
        input2.pseudo_commitment = Some("ff".repeat(32));
        assert!(parse_confidential_input(&input2).is_none());

        let (mut input3, _, _) = make_conf_input();
        input3.ring_commitments = None;
        assert!(parse_confidential_input(&input3).is_none());
    }

    #[test]
    fn parse_output_happy_and_reject() {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = generator_h();
        let blind = Scalar::random(&mut OsRng);
        let commitment = Scalar::from(9u64) * h + blind * g;
        let otk = Scalar::random(&mut OsRng) * g;
        let eph = Scalar::random(&mut OsRng) * g;
        let proof = prove(9u64, &blind);
        let output = TxOutput {
            address: "SD1s".into(),
            amount: 0,
            commitment: Some(hexp(&commitment)),
            range_proof: Some(range_proof_to_hex(&proof)),
            ephemeral_pubkey: Some(hexp(&eph)),
            one_time_pubkey: Some(hexp(&otk)),
            encrypted_amount: None,
        };
        let view = parse_confidential_output(&output).expect("parse");
        assert_eq!(view.commitment, commitment);
        assert_eq!(view.one_time_pubkey, otk);

        let mut bad = output.clone();
        bad.one_time_pubkey = Some("ff".repeat(32));
        assert!(parse_confidential_output(&bad).is_none());
    }
}
