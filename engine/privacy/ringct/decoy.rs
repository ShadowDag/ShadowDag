// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

//! Decoy (ring member) selection for confidential transactions. Samples real
//! on-chain confidential outputs uniformly from the global output index. The
//! distribution is uniform; a recency-weighted policy (Monero gamma) is a later
//! refinement and is not a consensus concern (consensus only checks members are
//! real on-chain outputs).

use crate::domain::utxo::utxo_set::UtxoSet;
use crate::engine::privacy::ringct::dual_clsag::RingMember;
use crate::engine::privacy::ringct::serialization::point_from_hex;
use std::collections::HashSet;

/// Select `count` distinct real confidential outputs as ring members, skipping
/// any one-time pubkey hex in `exclude`. Returns `None` if fewer than `count`
/// eligible outputs exist or the index is malformed.
pub fn select_decoys(
    utxo_set: &UtxoSet,
    count: usize,
    exclude: &[String],
) -> Option<Vec<RingMember>> {
    use rand::rngs::OsRng;
    use rand::Rng;

    if count == 0 {
        return Some(Vec::new());
    }
    let total = utxo_set.confidential_output_count();
    if total == 0 {
        return None;
    }
    let excluded: HashSet<&str> = exclude.iter().map(|s| s.as_str()).collect();

    let mut chosen_keys: HashSet<String> = HashSet::new();
    let mut members: Vec<RingMember> = Vec::with_capacity(count);
    // Bounded attempts: enough to almost surely fill when eligible >= count,
    // and to terminate (returning None) when it cannot.
    let max_attempts = total.saturating_mul(8).max(64);
    let mut attempts = 0u64;
    let mut rng = OsRng;

    while members.len() < count && attempts < max_attempts {
        attempts += 1;
        let idx = rng.gen_range(0..total);
        let pk = match utxo_set.confidential_output_at(idx) {
            Some(p) => p,
            None => continue,
        };
        if excluded.contains(pk.as_str()) || chosen_keys.contains(&pk) {
            continue;
        }
        let c_hex = match utxo_set.output_key_commitment(&pk) {
            Some(c) => c,
            None => continue,
        };
        let public_key = match point_from_hex(&pk) {
            Some(p) => p,
            None => continue,
        };
        let commitment = match point_from_hex(&c_hex) {
            Some(c) => c,
            None => continue,
        };
        chosen_keys.insert(pk);
        members.push(RingMember {
            public_key,
            commitment,
        });
    }

    if members.len() == count {
        Some(members)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
    use rand::rngs::OsRng;

    fn hx(p: &RistrettoPoint) -> String {
        hex::encode(p.compress().as_bytes())
    }

    /// Record `n` random confidential outputs; return their pubkey hexes.
    fn seed_outputs(set: &UtxoSet, n: usize) -> Vec<String> {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = crate::engine::privacy::confidential::pedersen::generator_h();
        let mut keys = Vec::new();
        for _ in 0..n {
            let pk = Scalar::random(&mut OsRng) * g;
            let c = Scalar::from(5u64) * h + Scalar::random(&mut OsRng) * g;
            set.record_confidential_output_indexed(&hx(&pk), &hx(&c))
                .unwrap();
            keys.push(hx(&pk));
        }
        keys
    }

    #[test]
    fn selects_distinct_real_members_excluding() {
        let set = UtxoSet::new_empty();
        let keys = seed_outputs(&set, 10);
        let exclude = vec![keys[0].clone(), keys[1].clone()];
        let ring = select_decoys(&set, 4, &exclude).expect("enough outputs");
        assert_eq!(ring.len(), 4);
        let mut seen = HashSet::new();
        for m in &ring {
            let pk = hx(&m.public_key);
            assert!(seen.insert(pk.clone()), "distinct members");
            assert!(!exclude.contains(&pk), "excluded key must not appear");
            assert_eq!(set.output_key_commitment(&pk), Some(hx(&m.commitment)));
        }
    }

    #[test]
    fn returns_none_when_insufficient() {
        let set = UtxoSet::new_empty();
        let keys = seed_outputs(&set, 3);
        let exclude = vec![keys[0].clone(), keys[1].clone()];
        assert!(select_decoys(&set, 3, &exclude).is_none());
        let empty = UtxoSet::new_empty();
        assert!(select_decoys(&empty, 1, &[]).is_none());
        assert_eq!(select_decoys(&set, 0, &[]).map(|v| v.len()), Some(0));
    }

    #[test]
    fn ring_from_select_decoys_builds_consensus_valid_tx() {
        use crate::config::node::node_config::NetworkMode;
        use crate::engine::privacy::ringct::builder::{
            build_confidential_transaction, ConfRecipient, OwnedInput,
        };
        use crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx;
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = crate::engine::privacy::confidential::pedersen::generator_h();
        let set = UtxoSet::new_empty();
        seed_outputs(&set, 20);

        // The spender's real output (amount 100), recorded + indexed.
        let spend = Scalar::random(&mut OsRng);
        let bl = Scalar::random(&mut OsRng);
        let real_pk = spend * g;
        let real_c = Scalar::from(100u64) * h + bl * g;
        set.record_confidential_output_indexed(&hx(&real_pk), &hx(&real_c))
            .unwrap();

        // Ring: 4 decoys from the index (excluding the real key) + the real one.
        let mut ring: Vec<RingMember> =
            select_decoys(&set, 4, &[hx(&real_pk)]).expect("decoys");
        ring.push(RingMember {
            public_key: real_pk,
            commitment: real_c,
        });
        let real_index = ring.len() - 1;

        let owned = OwnedInput {
            spend_secret: spend,
            amount: 100,
            blinding: bl,
            ring,
            real_index,
        };
        let net = NetworkMode::Mainnet;
        let vp = Scalar::random(&mut OsRng) * g;
        let sp = Scalar::random(&mut OsRng) * g;
        let tx = build_confidential_transaction(
            vec![owned],
            vec![ConfRecipient {
                view_pub: vp,
                spend_pub: sp,
                amount: 100,
            }],
            0,
            &net,
        )
        .unwrap();

        let mut seen = HashSet::new();
        assert!(
            verify_confidential_tx(&tx, &set, &net, &mut seen).is_ok(),
            "a ring built from select_decoys must be consensus-valid"
        );
    }
}
