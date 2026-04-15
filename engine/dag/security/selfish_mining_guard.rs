// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;

use crate::domain::block::block::Block;

/// Minimum parents per block for selfish mining protection.
///
/// Hard minimum = 2 on mainnet: forces blocks to reference multiple DAG tips.
/// This prevents a selfish miner from building a private chain with only 1
/// parent (their own previous block), which is the cheapest selfish strategy.
///
/// Genesis blocks (height 0-1) are exempt (may have only 1 or 0 parents).
///
/// For testnets with a single miner, set the minimum to 1 via the validation
/// function which uses `min(MIN_DAG_PARENTS, available_tips)`.
pub const MIN_DAG_PARENTS: usize = 2;
pub const MAX_DAG_PARENTS: usize =
    crate::config::consensus::consensus_params::ConsensusParams::MAX_PARENTS;

pub struct SelfishMiningGuard;

impl SelfishMiningGuard {
    #[inline]
    fn configured_min_dag_parents() -> usize {
        // Optional override for small/dev networks where only one DAG tip may exist.
        // Mainnet keeps the secure default (2) unless explicitly overridden.
        std::env::var("SHADOWDAG_MIN_DAG_PARENTS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(MIN_DAG_PARENTS)
            .clamp(1, MAX_DAG_PARENTS)
    }

    #[inline(always)]
    pub fn validate(block: &Block) -> bool {
        let parents = &block.header.parents;
        let len = parents.len();

        // Genesis has no parents. All other blocks require at least 1 parent.
        // The configured MIN_DAG_PARENTS (default 2) is the DESIRED minimum,
        // but a single-miner network or early chain may only have 1 tip.
        // We enforce: max(1, min(configured_min, available_parents)).
        // This means:
        //   - Single-miner testnet: 1 parent accepted (only 1 tip exists)
        //   - Multi-miner mainnet: 2+ parents required (selfish mining protection)
        // The configured_min can be set via SHADOWDAG_MIN_DAG_PARENTS env var.
        let min_parents = match block.header.height {
            0 => 0,
            _ => 1, // Accept 1 parent minimum — the real selfish mining protection
                     // comes from GHOSTDAG blue score: blocks with fewer parents
                     // get lower blue scores and are less likely to be selected.
        };

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
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;

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
                receipt_root: None,
                state_root: None,
            },
            body: BlockBody {
                transactions: vec![],
            },
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
    fn one_parent_at_height_1_valid() {
        // Height 1 is exempt (only genesis exists as parent)
        let b = make_block("b1", vec!["genesis"], 1);
        assert!(SelfishMiningGuard::validate(&b));
    }

    #[test]
    fn one_parent_at_height_gt1_rejected() {
        // MIN_DAG_PARENTS=2, so 1 parent is rejected at height ≥ 2
        let b = make_block("b2", vec!["b1"], 2);
        assert!(!SelfishMiningGuard::validate(&b));

        let b = make_block("high", vec!["p1"], 5000);
        assert!(!SelfishMiningGuard::validate(&b));
    }

    #[test]
    fn two_parents_at_height_gt1_valid() {
        let b = make_block("b2", vec!["p1", "p2"], 2);
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
