// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;

use crate::config::node::node_config::NetworkMode;
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
    /// Minimum DAG parents required at a given height.
    ///
    /// SECURITY: this is a CONSENSUS rule and is a pure function of `height`
    /// plus the fixed `MIN_DAG_PARENTS` constant. It MUST NOT depend on process
    /// environment — a previous version read `SHADOWDAG_MIN_DAG_PARENTS` /
    /// `NETWORK` env vars here, which let two honest nodes disagree on block
    /// validity (one accepting a 1-parent block at height ≥ 2, the other
    /// rejecting it) and permanently fork the chain. Any per-network relaxation
    /// for single-miner dev networks must be threaded explicitly via
    /// `NetworkMode`, never via the environment.
    #[inline]
    pub fn configured_min_dag_parents_for_height(height: u64) -> usize {
        Self::min_dag_parents_for(height, NetworkMode::Mainnet)
    }

    /// Network-aware minimum DAG parents at `height`.
    ///
    /// Mainnet enforces the 2-parent anti-selfish-mining rule at height >= 2.
    /// Test networks (testnet/regtest) allow LINEAR (single-parent) chains so a
    /// small number of miners can bootstrap from a single genesis: the 2-parent
    /// rule deadlocks a fresh chain (one tip can never produce a 2-parent child).
    /// This IS a consensus rule, but keyed purely on the fixed `NetworkMode`, so
    /// every node on a given network agrees — no fork (unlike an env-var switch,
    /// which two honest nodes could read differently).
    #[inline]
    pub fn min_dag_parents_for(height: u64, network: NetworkMode) -> usize {
        match network {
            NetworkMode::Mainnet => match height {
                0 => 0,
                1 => 1,
                _ => MIN_DAG_PARENTS,
            },
            NetworkMode::Testnet | NetworkMode::Regtest => {
                if height == 0 {
                    0
                } else {
                    1
                }
            }
        }
    }

    #[inline(always)]
    pub fn validate(block: &Block) -> bool {
        Self::validate_for_network(block, NetworkMode::Mainnet)
    }

    /// Network-aware variant of [`validate`]; the consensus path passes the
    /// node's `NetworkMode` so test networks accept linear chains.
    #[inline(always)]
    pub fn validate_for_network(block: &Block, network: NetworkMode) -> bool {
        let parents = &block.header.parents;
        let len = parents.len();

        let min_parents = Self::min_dag_parents_for(block.header.height, network);

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
                mix_hash: String::new(),
                prev_state_commitment: None,
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

    #[test]
    fn min_parents_is_environment_independent() {
        // Consensus rule must NOT be influenced by env vars (fork-prevention).
        std::env::set_var("NETWORK", "regtest");
        std::env::set_var("SHADOWDAG_MIN_DAG_PARENTS", "1");
        let min = SelfishMiningGuard::configured_min_dag_parents_for_height(2);
        std::env::remove_var("SHADOWDAG_MIN_DAG_PARENTS");
        std::env::remove_var("NETWORK");
        assert_eq!(min, MIN_DAG_PARENTS, "env must not weaken the min-parent rule");
        // Height schedule is fixed.
        assert_eq!(SelfishMiningGuard::configured_min_dag_parents_for_height(0), 0);
        assert_eq!(SelfishMiningGuard::configured_min_dag_parents_for_height(1), 1);
    }

    #[test]
    fn testnet_allows_linear_chain_mainnet_does_not() {
        use crate::config::node::node_config::NetworkMode;
        // A 1-parent block at height >= 2: mainnet rejects (anti-selfish-mining),
        // test networks accept so a fresh chain can bootstrap from one genesis.
        let b = make_block("b2", vec!["b1"], 2);
        assert!(!SelfishMiningGuard::validate(&b)); // mainnet default
        assert!(SelfishMiningGuard::validate_for_network(&b, NetworkMode::Testnet));
        assert!(SelfishMiningGuard::validate_for_network(&b, NetworkMode::Regtest));
        // Parent-count schedule by network.
        assert_eq!(SelfishMiningGuard::min_dag_parents_for(2, NetworkMode::Mainnet), 2);
        assert_eq!(SelfishMiningGuard::min_dag_parents_for(2, NetworkMode::Testnet), 1);
        assert_eq!(SelfishMiningGuard::min_dag_parents_for(0, NetworkMode::Testnet), 0);
        // Genesis still needs 0 parents everywhere; height-1 still 1.
        assert!(SelfishMiningGuard::validate_for_network(
            &make_block("g", vec![], 0),
            NetworkMode::Testnet
        ));
    }
}
