// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::engine::dag::ghostdag::ghostdag::GhostDag;
use crate::config::checkpoints::Checkpoints;
use crate::errors::ConsensusError;

pub struct ChainManager;

impl ChainManager {

    // ─────────────────────────────────────────
    // CHAIN COMPARISON
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn is_better_chain(
        candidate: &str,
        current:   &str,
        ghostdag:  &GhostDag,
    ) -> bool {

        if candidate == current {
            return false;
        }

        let score_c = ghostdag.get_blue_score(candidate);
        let score_k = ghostdag.get_blue_score(current);

        match score_c.cmp(&score_k) {
            core::cmp::Ordering::Greater => true,
            core::cmp::Ordering::Less    => false,
            core::cmp::Ordering::Equal   => candidate < current, // deterministic tie-break
        }
    }

    // ─────────────────────────────────────────
    // BEST TIP (🔥 optimized + minimal branching)
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn best_tip<'a>(
        tips: &'a [String],
        ghostdag: &GhostDag,
    ) -> Option<&'a str> {

        let first = tips.first()?;

        let mut best = first;
        let mut best_score = ghostdag.get_blue_score(best);

        for tip in &tips[1..] {

            let score = ghostdag.get_blue_score(tip);

            if score > best_score {
                best = tip;
                best_score = score;
                continue;
            }

            if score == best_score && tip < best {
                best = tip;
            }
        }

        Some(best.as_str())
    }

    // ─────────────────────────────────────────
    // REORG RULES
    // ─────────────────────────────────────────

    /// Check if a reorg to the given fork point is allowed.
    ///
    /// Two layers of protection:
    ///   1. Checkpoint enforcement: cannot reorg below the last checkpoint
    ///   2. Finality depth: cannot reorg deeper than FINALITY_DEPTH blocks
    ///
    /// Both checks must pass for the reorg to be allowed.
    #[inline(always)]
    pub fn reorg_allowed(
        fork_height: u64,
        _new_tip_hash: &str,
        new_tip_height: u64,
    ) -> bool {
        // Layer 1: Checkpoint enforcement — cannot reorg below last checkpoint
        if let Some(cp) = Checkpoints::last_checkpoint() {
            if fork_height < cp.height {
                return false;
            }
        }

        // Layer 2: Finality depth — cannot reorg deeper than FINALITY_DEPTH
        use crate::engine::consensus::reorg::FINALITY_DEPTH;
        if new_tip_height > FINALITY_DEPTH {
            let finality_height = new_tip_height - FINALITY_DEPTH;
            if fork_height < finality_height {
                return false;
            }
        }

        true
    }

    // ─────────────────────────────────────────
    // CHECKPOINT VALIDATION
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn validate_checkpoint(
        height: u64,
        hash:   &str,
    ) -> Result<(), ConsensusError> {

        if Checkpoints::is_valid(height, hash) {
            return Ok(());
        }

        Err(ConsensusError::BlockValidation(format!(
            "[ChainManager] checkpoint conflict at height {}: hash {} rejected",
            height, hash
        )))
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

        GhostDag::new(&format!("/tmp/test_cm_{}", ts))
            .expect("test GhostDag DB open failed")
    }

    #[test]
    fn higher_score_wins() {
        let gd = make_gd();

        gd.store_blue_score("A", 100);
        gd.store_blue_score("B", 50);

        assert!(ChainManager::is_better_chain("A", "B", &gd));
        assert!(!ChainManager::is_better_chain("B", "A", &gd));
    }

    #[test]
    fn equal_score_tiebreak_by_hash() {
        let gd = make_gd();

        gd.store_blue_score("aaa", 50);
        gd.store_blue_score("bbb", 50);

        assert!(ChainManager::is_better_chain("aaa", "bbb", &gd));
        assert!(!ChainManager::is_better_chain("bbb", "aaa", &gd));
    }

    #[test]
    fn same_tip_is_not_better() {
        let gd = make_gd();

        gd.store_blue_score("X", 99);

        assert!(!ChainManager::is_better_chain("X", "X", &gd));
    }

    #[test]
    fn best_tip_picks_highest_score() {
        let gd = make_gd();

        gd.store_blue_score("T1", 10);
        gd.store_blue_score("T2", 30);
        gd.store_blue_score("T3", 20);

        let tips = vec![
            "T1".to_string(),
            "T2".to_string(),
            "T3".to_string(),
        ];

        assert_eq!(ChainManager::best_tip(&tips, &gd), Some("T2"));
    }

    #[test]
    fn best_tip_empty_returns_none() {
        let gd = make_gd();

        assert_eq!(ChainManager::best_tip(&[], &gd), None);
    }

    #[test]
    fn reorg_allowed_above_checkpoint() {
        assert!(ChainManager::reorg_allowed(1, "any", 5));
    }

    #[test]
    fn reorg_blocked_below_checkpoint() {
        assert!(ChainManager::reorg_allowed(0, "any", 1));
    }

    #[test]
    fn validate_checkpoint_genesis_ok() {
        let genesis = crate::config::genesis::genesis::genesis_hash();

        assert!(ChainManager::validate_checkpoint(0, &genesis).is_ok());
    }

    #[test]
    fn validate_checkpoint_wrong_hash_rejected() {
        let result = ChainManager::validate_checkpoint(0, "deadbeef");

        assert!(result.is_err(), "Wrong genesis hash must be rejected");
    }

    #[test]
    fn validate_checkpoint_unknown_height_ok() {
        assert!(ChainManager::validate_checkpoint(999_999, "anything").is_ok());
    }
}