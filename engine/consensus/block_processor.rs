// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;

use crate::engine::dag::ghostdag::ghostdag::GhostDag;
use crate::engine::consensus::chain_manager::ChainManager;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::errors::ConsensusError;
use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;

pub struct BlockProcessor;

impl BlockProcessor {

    // ─────────────────────────────────────────
    // REORG CHECK
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn is_reorg_needed(
        current_tip:   &str,
        candidate_tip: &str,
        ghostdag:      &GhostDag,
    ) -> bool {
        ChainManager::is_better_chain(candidate_tip, current_tip, ghostdag)
    }

    // ─────────────────────────────────────────
    // FIND FORK
    // ─────────────────────────────────────────

    pub fn find_fork_point(
        tip_a:     &str,
        tip_b:     &str,
        ghostdag:  &GhostDag,
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
                None    => break,
            }
        }

        let mut current = tip_b.to_owned();

        for _ in 0..max_depth {

            if visited.contains(&current) {
                return Some(current);
            }

            match ghostdag.get_selected_parent(&current) {
                Some(p) => current = p,
                None    => break,
            }
        }

        None
    }

    // ─────────────────────────────────────────
    // HANDLE REORG
    // ─────────────────────────────────────────

    pub fn handle_reorg(
        old_tip:     &str,
        new_tip:     &str,
        utxo_set:    &UtxoSet,
        block_store: &BlockStore,
        ghostdag:    &GhostDag,
        max_depth:   usize,
    ) -> Result<String, ConsensusError> {

        if old_tip == new_tip {
            return Ok(old_tip.to_owned());
        }

        // SECURITY: Verify the new tip has HIGHER blue score than the old tip.
        // Without this check, an attacker can force a reorg to a weaker chain,
        // reversing confirmed transactions.
        let old_score = ghostdag.get_blue_score(old_tip);
        let new_score = ghostdag.get_blue_score(new_tip);
        if new_score <= old_score {
            return Err(ConsensusError::ReorgRejected(format!(
                "new tip blue_score {} <= old tip blue_score {} — refusing weaker chain",
                new_score, old_score
            )));
        }

        let fork = Self::find_fork_point(old_tip, new_tip, ghostdag, max_depth)
            .ok_or_else(|| {
                ConsensusError::ReorgRejected(format!(
                    "[BlockProcessor] no fork between {} and {}",
                    &old_tip[..old_tip.len().min(8)],
                    &new_tip[..new_tip.len().min(8)],
                ))
            })?;

        // ───────── BUILD CHAINS ─────────

        let rollback_chain = Self::collect_chain(old_tip, &fork, ghostdag, max_depth);

        let mut apply_chain = Self::collect_chain(new_tip, &fork, ghostdag, max_depth);
        apply_chain.reverse();

        // ───────── ROLLBACK ─────────

        for hash in &rollback_chain {

            let block = block_store.get_block(hash)
                .ok_or_else(|| ConsensusError::Other(format!("missing block {}", hash)))?;

            #[allow(deprecated)]
            utxo_set.rollback_block(&block.body.transactions)
                .map_err(|e| ConsensusError::ReorgRejected(format!("rollback failed at {}: {}", hash, e)))?;
        }

        // ───────── APPLY ─────────

        let mut applied: Vec<String> = Vec::with_capacity(apply_chain.len());

        for hash in &apply_chain {

            let block = block_store.get_block(hash)
                .ok_or_else(|| ConsensusError::Other(format!("missing block {}", hash)))?;

            let height = block.header.height;

            if let Err(e) = utxo_set.apply_block(&block.body.transactions, height) {

                // 🔥 rollback partial apply
                for prev in applied.iter().rev() {
                    if let Some(b) = block_store.get_block(prev) {
                        #[allow(deprecated)]
                        let _ = utxo_set.rollback_block(&b.body.transactions);
                    }
                }

                // 🔥 restore old chain
                for h in rollback_chain.iter().rev() {
                    if let Some(b) = block_store.get_block(h) {
                        let _ = utxo_set.apply_block(&b.body.transactions, b.header.height);
                    }
                }

                return Err(ConsensusError::ReorgRejected(format!("apply failed at {}: {}", hash, e)));
            }

            applied.push(hash.clone());
        }

        Ok(fork)
    }

    // ─────────────────────────────────────────
    // COLLECT CHAIN
    // ─────────────────────────────────────────

    #[inline(always)]
    fn collect_chain(
        tip:      &str,
        stop:     &str,
        ghostdag: &GhostDag,
        max_depth: usize,
    ) -> Vec<String> {

        let mut chain = Vec::with_capacity(max_depth);

        let mut current = tip.to_owned();

        for _ in 0..max_depth {

            if current == stop {
                break;
            }

            chain.push(current.clone());

            match ghostdag.get_selected_parent(&current) {
                Some(p) => current = p,
                None    => break,
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

        GhostDag::new(&format!("/tmp/test_bp_{}", ts))
            .expect("test GhostDag DB open failed")
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