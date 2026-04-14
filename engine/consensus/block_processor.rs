// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;

use crate::domain::utxo::utxo_set::UtxoSet;
use crate::engine::consensus::chain_manager::ChainManager;
use crate::engine::dag::ghostdag::ghostdag::GhostDag;
use crate::errors::ConsensusError;
use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;
use crate::slog_error;

pub struct BlockProcessor;

impl BlockProcessor {
    // ─────────────────────────────────────────
    // REORG CHECK
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn is_reorg_needed(current_tip: &str, candidate_tip: &str, ghostdag: &GhostDag) -> bool {
        ChainManager::is_better_chain(candidate_tip, current_tip, ghostdag)
    }

    // ─────────────────────────────────────────
    // FIND FORK
    // ─────────────────────────────────────────

    /// Find the common ancestor (fork point) of two chain tips by walking
    /// back through selected parents up to `max_depth` steps from each tip.
    ///
    /// # Truncation behavior
    /// Returns `None` if no common ancestor is found within `max_depth` steps.
    /// This can happen either because the chains truly share no common ancestor
    /// (disjoint DAGs) **or** because the fork point is deeper than `max_depth`.
    /// Callers should treat `None` as an error when a fork point is expected
    /// to exist (e.g., during reorgs on the same network).
    pub fn find_fork_point(
        tip_a: &str,
        tip_b: &str,
        ghostdag: &GhostDag,
        max_depth: usize,
    ) -> Option<String> {
        if tip_a == tip_b {
            return Some(tip_a.to_owned());
        }

        let mut visited = HashSet::with_capacity(max_depth);

        let mut current = tip_a.to_owned();

        for _ in 0..max_depth {
            visited.insert(current.clone());

            match ghostdag.get_selected_parent(&current) {
                Some(p) => current = p,
                None => break,
            }
        }

        let mut current = tip_b.to_owned();

        for _ in 0..max_depth {
            if visited.contains(&current) {
                return Some(current);
            }

            match ghostdag.get_selected_parent(&current) {
                Some(p) => current = p,
                None => break,
            }
        }

        None
    }

    // ─────────────────────────────────────────
    // HANDLE REORG
    // ─────────────────────────────────────────

    pub fn handle_reorg(
        old_tip: &str,
        new_tip: &str,
        utxo_set: &UtxoSet,
        block_store: &BlockStore,
        ghostdag: &GhostDag,
        max_depth: usize,
    ) -> Result<String, ConsensusError> {
        if old_tip == new_tip {
            return Ok(old_tip.to_owned());
        }

        // SECURITY: Verify the new tip has HIGHER blue score than the old tip.
        // Without this check, an attacker can force a reorg to a weaker chain,
        // reversing confirmed transactions.
        let old_score = ghostdag.get_blue_score(old_tip);
        let new_score = ghostdag.get_blue_score(new_tip);
        if new_score < old_score {
            return Err(ConsensusError::ReorgRejected(format!(
                "new tip blue_score {} < old tip blue_score {} — refusing weaker chain",
                new_score, old_score
            )));
        }
        // Equal score: apply deterministic tie-break (lower hash wins)
        if new_score == old_score && new_tip >= old_tip {
            return Err(ConsensusError::ReorgRejected(format!(
                "new tip blue_score {} == old tip {} but hash {} >= {} — tie lost",
                new_score,
                old_score,
                &new_tip[..16.min(new_tip.len())],
                &old_tip[..16.min(old_tip.len())]
            )));
        }

        let fork =
            Self::find_fork_point(old_tip, new_tip, ghostdag, max_depth).ok_or_else(|| {
                ConsensusError::ReorgRejected(format!(
                    "[BlockProcessor] no fork between {} and {}",
                    &old_tip[..old_tip.len().min(8)],
                    &new_tip[..new_tip.len().min(8)],
                ))
            })?;

        // ───────── BUILD CHAINS ─────────

        let rollback_chain = Self::collect_chain(old_tip, &fork, ghostdag, max_depth);

        let mut apply_chain = Self::collect_chain(new_tip, &fork, ghostdag, max_depth);

        // Verify chains reached the fork point (no silent truncation).
        // If collect_chain hit max_depth before reaching `fork`, the
        // chain is incomplete and applying it would corrupt UTXO state.
        if !rollback_chain.is_empty() {
            let last_rollback = &rollback_chain[rollback_chain.len() - 1];
            if let Some(parent) = ghostdag.get_selected_parent(last_rollback) {
                if parent != fork {
                    return Err(ConsensusError::ReorgRejected(format!(
                        "rollback chain truncated at depth {} (last block parent {} != fork {})",
                        rollback_chain.len(),
                        &parent[..parent.len().min(8)],
                        &fork[..fork.len().min(8)]
                    )));
                }
            }
        }
        if !apply_chain.is_empty() {
            let last_apply = &apply_chain[apply_chain.len() - 1];
            if let Some(parent) = ghostdag.get_selected_parent(last_apply) {
                if parent != fork {
                    return Err(ConsensusError::ReorgRejected(format!(
                        "apply chain truncated at depth {} (last block parent {} != fork {})",
                        apply_chain.len(),
                        &parent[..parent.len().min(8)],
                        &fork[..fork.len().min(8)]
                    )));
                }
            }
        }

        apply_chain.reverse();

        // ───────── ROLLBACK ─────────

        for hash in &rollback_chain {
            let block = block_store
                .get_block(hash)
                .ok_or_else(|| ConsensusError::Other(format!("missing block {}", hash)))?;

            #[allow(deprecated)]
            utxo_set
                .rollback_block(&block.body.transactions)
                .map_err(|e| {
                    ConsensusError::ReorgRejected(format!("rollback failed at {}: {}", hash, e))
                })?;
        }

        // ───────── APPLY ─────────

        let mut applied: Vec<String> = Vec::with_capacity(apply_chain.len());

        for hash in &apply_chain {
            let block = block_store
                .get_block(hash)
                .ok_or_else(|| ConsensusError::Other(format!("missing block {}", hash)))?;

            let height = block.header.height;

            if let Err(e) =
                utxo_set.apply_block(&block.body.transactions, height, &block.header.hash)
            {
                let original_error = format!("apply failed at {}: {}", hash, e);

                // rollback partial apply
                let mut restore_failed = false;
                let mut restore_err_msg = String::new();
                for prev in applied.iter().rev() {
                    if let Some(b) = block_store.get_block(prev) {
                        #[allow(deprecated)]
                        if let Err(re) = utxo_set.rollback_block(&b.body.transactions) {
                            slog_error!("consensus", "restore_after_failed_reorg", error => re);
                            restore_failed = true;
                            restore_err_msg = format!("{}", re);
                        }
                    }
                }

                // restore old chain
                for h in rollback_chain.iter().rev() {
                    if let Some(b) = block_store.get_block(h) {
                        if let Err(re) = utxo_set.apply_block(
                            &b.body.transactions,
                            b.header.height,
                            &b.header.hash,
                        ) {
                            slog_error!("consensus", "critical_restore_failed_during_reorg", error => re);
                            restore_failed = true;
                            restore_err_msg = format!("{}", re);
                        }
                    }
                }

                if restore_failed {
                    return Err(ConsensusError::Other(format!(
                        "CRITICAL: reorg failed ({}) AND restore also failed ({}). UTXO state may be inconsistent.",
                        original_error, restore_err_msg
                    )));
                }

                return Err(ConsensusError::ReorgRejected(original_error));
            }

            applied.push(hash.clone());
        }

        Ok(new_tip.to_string())
    }

    // ─────────────────────────────────────────
    // COLLECT CHAIN
    // ─────────────────────────────────────────

    /// Collect the chain of block hashes from `tip` back toward `stop`
    /// (exclusive of `stop`), following selected parents up to `max_depth` steps.
    ///
    /// # Truncation behavior
    /// If `stop` is not reached within `max_depth` steps, the returned chain
    /// is silently truncated -- it will contain only the blocks encountered
    /// before the depth limit was hit. The chain may also be truncated if a
    /// block has no selected parent (e.g., genesis). Callers that require a
    /// complete path should verify that the last element's parent equals `stop`.
    #[inline(always)]
    fn collect_chain(tip: &str, stop: &str, ghostdag: &GhostDag, max_depth: usize) -> Vec<String> {
        let mut chain = Vec::with_capacity(max_depth);

        let mut current = tip.to_owned();

        for _ in 0..max_depth {
            if current == stop {
                break;
            }

            chain.push(current.clone());

            match ghostdag.get_selected_parent(&current) {
                Some(p) => current = p,
                None => break,
            }
        }

        chain
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {

    use super::*;
    use crate::engine::dag::ghostdag::ghostdag::GhostDag;

    fn make_gd() -> GhostDag {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        GhostDag::new(&format!("/tmp/test_bp_{}", ts)).expect("test GhostDag DB open failed")
    }

    fn set_sp(gd: &GhostDag, child: &str, parent: &str) {
        let key = format!("gd:sp:{}", child);
        gd.db().put(key.as_bytes(), parent.as_bytes()).ok();
    }

    #[test]
    fn find_fork_same_tip_returns_self() {
        let gd = make_gd();

        assert_eq!(
            BlockProcessor::find_fork_point("A", "A", &gd, 100),
            Some("A".to_string())
        );
    }

    #[test]
    fn find_fork_linear_chains() {
        let gd = make_gd();

        set_sp(&gd, "C", "B");
        set_sp(&gd, "B", "A");
        set_sp(&gd, "A", "genesis");

        set_sp(&gd, "E", "D");
        set_sp(&gd, "D", "B");

        let fork = BlockProcessor::find_fork_point("C", "E", &gd, 100);

        assert_eq!(fork, Some("B".to_string()));
    }

    #[test]
    fn find_fork_no_common_ancestor() {
        let gd = make_gd();

        set_sp(&gd, "X", "X1");
        set_sp(&gd, "Y", "Y1");

        let fork = BlockProcessor::find_fork_point("X", "Y", &gd, 5);

        assert!(fork.is_none());
    }

    #[test]
    fn is_reorg_needed_higher_score() {
        let gd = make_gd();

        gd.store_blue_score("tip_old", 10);
        gd.store_blue_score("tip_new", 20);

        assert!(BlockProcessor::is_reorg_needed("tip_old", "tip_new", &gd));
        assert!(!BlockProcessor::is_reorg_needed("tip_new", "tip_old", &gd));
    }

    #[test]
    fn is_reorg_needed_same_score_tiebreak() {
        let gd = make_gd();

        gd.store_blue_score("zzz", 50);
        gd.store_blue_score("aaa", 50);

        assert!(BlockProcessor::is_reorg_needed("zzz", "aaa", &gd));
        assert!(!BlockProcessor::is_reorg_needed("aaa", "zzz", &gd));
    }
}
