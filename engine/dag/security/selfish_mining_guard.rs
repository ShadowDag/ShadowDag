// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;

use crate::domain::block::block::Block;

/// Minimum parents per block for selfish mining protection.
///
/// Hard minimum = 1: every non-genesis block MUST reference at least 1 parent.
/// Soft target  = 2: blocks with fewer parents than available tips get lower
///                    GHOSTDAG scores, creating an economic incentive to include
///                    all tips without hard-rejecting honest miners on small networks.
///
/// Previous design used MIN=2 hard-reject, which broke single-miner testnets
/// where only 1 DAG tip exists. The fix: accept any block with ≥1 parent,
/// rely on GHOSTDAG scoring + getblocktemplate tip selection for connectivity.
pub const MIN_DAG_PARENTS: usize = 1;
pub const MAX_DAG_PARENTS: usize = crate::config::consensus::consensus_params::ConsensusParams::MAX_PARENTS;

pub struct SelfishMiningGuard;

impl SelfishMiningGuard {

    #[inline(always)]
    pub fn validate(block: &Block) -> bool {

        let parents = &block.header.parents;
        let len = parents.len();

        // Genesis has no parents; all other blocks need at least 1 parent.
        let min_parents = if block.header.height == 0 { 0 } else { MIN_DAG_PARENTS };

        // 1️⃣ Range
        if len < min_parents || len > MAX_DAG_PARENTS {
            return false;
        }

        let self_hash = &block.header.hash;

        // 2️⃣ Duplicate + sanity
        let mut seen = HashSet::with_capacity(len);

        for parent in parents {

            // ❌ empty
            if parent.is_empty() {
                return false;
            }

            // ❌ whitespace-only (بدون iterator)
            let mut has_non_ws = false;
            for &b in parent.as_bytes() {
                if !b.is_ascii_whitespace() {
                    has_non_ws = true;
                    break;
                }
            }
            if !has_non_ws {
                return false;
            }

            // ❌ self reference
            if parent == self_hash {
                return false;
            }

            // ❌ duplicate
            if !seen.insert(parent) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::block::block_body::BlockBody;

    fn make_block(hash: &str, parents: Vec<&str>, height: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                hash: hash.to_string(),
                parents: parents.into_iter().map(|s| s.to_string()).collect(),
                merkle_root: "mr".into(),
                timestamp: 1000,
                nonce: 1,
                difficulty: 1,
                height,
                blue_score: 0,
                selected_parent: None,
                utxo_commitment: None,
                extra_nonce: 0,
            },
            body: BlockBody { transactions: vec![] },
        }
    }

    #[test]
    fn genesis_with_no_parents_valid() {
        let b = make_block("genesis", vec![], 0);
        assert!(SelfishMiningGuard::validate(&b));
    }

    #[test]
    fn height_1_with_one_parent_valid() {
        let b = make_block("b1", vec!["genesis"], 1);
        assert!(SelfishMiningGuard::validate(&b));
    }

    #[test]
    fn one_parent_at_any_height_valid() {
        // MIN_DAG_PARENTS=1, so 1 parent is always valid
        let b = make_block("b2", vec!["b1"], 2);
        assert!(SelfishMiningGuard::validate(&b));

        let b = make_block("high", vec!["p1"], 5000);
        assert!(SelfishMiningGuard::validate(&b));
    }

    #[test]
    fn height_2_with_two_parents_valid() {
        let b = make_block("b2", vec!["p1", "p2"], 2);
        assert!(SelfishMiningGuard::validate(&b));
    }

    #[test]
    fn no_parents_at_height_gt0_rejected() {
        // Non-genesis with 0 parents must be rejected
        let b = make_block("nope", vec![], 5);
        assert!(!SelfishMiningGuard::validate(&b));
    }

    #[test]
    fn self_reference_rejected() {
        let b = make_block("self_ref", vec!["self_ref", "other"], 2);
        assert!(!SelfishMiningGuard::validate(&b));
    }

    #[test]
    fn duplicate_parents_rejected() {
        let b = make_block("dup", vec!["p1", "p1"], 2);
        assert!(!SelfishMiningGuard::validate(&b));
    }

    #[test]
    fn empty_parent_hash_rejected() {
        let b = make_block("empty_p", vec!["", "valid"], 2);
        assert!(!SelfishMiningGuard::validate(&b));
    }

    #[test]
    fn whitespace_only_parent_rejected() {
        let b = make_block("ws", vec!["   ", "valid"], 2);
        assert!(!SelfishMiningGuard::validate(&b));
    }
}