// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::slog_warn;

pub const MAX_REORG_DEPTH: u64 = 1_000;

/// Minimum cumulative work ratio for reorg acceptance (integer math).
/// Expressed as numerator/denominator to avoid floating-point in consensus.
/// 100/100 = 1.0× = new chain must have ≥ old chain's work (standard rule).
/// To require 10% more work, set NUM=110, DEN=100.
pub const MIN_WORK_RATIO_NUM: u64 = 100;
pub const MIN_WORK_RATIO_DEN: u64 = 100;

/// Finality by cumulative work — once a block has this many difficulty units
/// of work built on top of it, it's considered economically final regardless
/// of depth. This prevents deep reorgs even if the attacker chain is longer.
pub const ECONOMIC_FINALITY_WORK: u64 = 10_000;

/// Finality depth — blocks deeper than this below the tip are considered
/// irreversible. Once a block reaches FINALITY_DEPTH confirmations:
///   1. No reorg can reach below it
///   2. Its undo data can be pruned to save disk space
///   3. It's reported as "finalized" to wallets/explorers
///
/// At 10 BPS, 100 blocks = 10 seconds. We use 200 blocks (~20s) which
/// provides strong probabilistic finality in a DAG (far more than the
/// ~60 minutes / 6 blocks Bitcoin requires, because DAG has parallel
/// confirmation from multiple miners simultaneously).
pub const FINALITY_DEPTH: u64 = 200;

#[derive(Debug, Clone, PartialEq)]
pub struct ReorgEvent {
    pub old_tip:         String,
    pub new_tip:         String,
    pub common_ancestor: String,
    pub depth:           u64,
    pub blocks_removed:  Vec<String>,
    pub blocks_added:    Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReorgResult {
    NoReorg,
    Extended(ReorgEvent),  // Chain grew without fork (depth=0, no blocks removed)
    Reorged(ReorgEvent),
    TooDeep,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReorgRejection {
    InsufficientWork { old: u64, new: u64 },
    ExceedsFinality { depth: u64 },
    DepthExceeded { depth: u64, max: u64 },
}

impl std::fmt::Display for ReorgRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientWork { old, new } => {
                write!(f, "insufficient work: old={}, new={}", old, new)
            }
            Self::ExceedsFinality { depth } => {
                write!(f, "block at depth {} is economically final", depth)
            }
            Self::DepthExceeded { depth, max } => {
                write!(f, "reorg depth {} exceeds max {}", depth, max)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CumulativeWork {
    /// Sum of difficulties for each block in the chain segment
    pub total_difficulty: u64,
    /// Number of blocks
    pub block_count: u64,
}

impl CumulativeWork {
    pub fn from_difficulties(difficulties: &[u64]) -> Self {
        Self {
            total_difficulty: difficulties.iter()
                .try_fold(0u64, |acc, &d| acc.checked_add(d))
                .unwrap_or(u64::MAX),
            block_count: difficulties.len() as u64,
        }
    }

    pub fn exceeds_finality(&self) -> bool {
        self.total_difficulty >= ECONOMIC_FINALITY_WORK
    }
}

pub struct ReorgManager {
    pub max_depth:   u64,
    pub reorg_count: u64,
    pub last_reorg:  Option<ReorgEvent>,
}

impl Default for ReorgManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ReorgManager {
    pub fn new() -> Self {
        Self {
            max_depth:   MAX_REORG_DEPTH,
            reorg_count: 0,
            last_reorg:  None,
        }
    }

    pub fn detect(
        &mut self,
        old_chain: &[String],
        new_chain: &[String],
    ) -> ReorgResult {

        if old_chain.is_empty() || new_chain.is_empty() {
            return ReorgResult::NoReorg;
        }

        let mut i = old_chain.len();
        let mut j = new_chain.len();

        let old_tip = &old_chain[i - 1];
        let new_tip = &new_chain[j - 1];

        // 1. Same tip
        if old_tip == new_tip {
            return ReorgResult::NoReorg;
        }

        // 2. Fast path (extension — chain grew, no fork)
        if j > i && new_chain[..i] == *old_chain {
            return ReorgResult::Extended(ReorgEvent {
                old_tip:         old_tip.clone(),
                new_tip:         new_tip.clone(),
                common_ancestor: old_tip.clone(),
                depth:           0,
                blocks_removed:  Vec::new(),
                blocks_added:    new_chain[i..].to_vec(),
            });
        }

        // 3. Align heights
        while i > j { i -= 1; }
        while j > i { j -= 1; }

        // 4. Walk + early depth stop
        let mut depth = 0;

        while i > 0 && j > 0 {
            if old_chain[i - 1] == new_chain[j - 1] {
                break;
            }

            i -= 1;
            j -= 1;
            depth += 1;

            if depth > self.max_depth {
                return ReorgResult::TooDeep;
            }
        }

        // No common ancestor found — treat as too deep to be safe.
        // Without a shared ancestor the fork cannot be evaluated reliably.
        if i == 0 || j == 0 {
            return ReorgResult::TooDeep;
        }

        let ancestor_idx_old = i - 1;
        let ancestor_idx_new = j - 1;

        let common_ancestor = &old_chain[ancestor_idx_old];

        let removed_slice = &old_chain[ancestor_idx_old + 1..];
        let added_slice   = &new_chain[ancestor_idx_new + 1..];

        let depth = removed_slice.len() as u64;

        if depth > self.max_depth {
            return ReorgResult::TooDeep;
        }

        let event = ReorgEvent {
            old_tip:         old_tip.clone(),
            new_tip:         new_tip.clone(),
            common_ancestor: common_ancestor.clone(),
            depth,
            blocks_removed:  removed_slice.to_vec(),
            blocks_added:    added_slice.to_vec(),
        };

        self.reorg_count += 1;
        self.last_reorg = Some(event.clone());

        ReorgResult::Reorged(event)
    }

    /// Economic reorg validation — checks that the new chain has sufficient
    /// cumulative work to justify the reorg.
    ///
    /// Returns `Ok(())` if the reorg should be allowed based on work comparison.
    /// When both chains have equal cumulative work, a deterministic hash-based
    /// tiebreaker is used: the chain with the lexicographically lower tip hash
    /// wins. This prevents deadlock between nodes that see different orderings
    /// (issue #42).
    pub fn validate_economic(
        &self,
        old_work: &CumulativeWork,
        new_work: &CumulativeWork,
        reorg_depth: u64,
        old_tip_hash: &str,
        new_tip_hash: &str,
    ) -> Result<(), ReorgRejection> {
        // 1. Depth check
        if reorg_depth > self.max_depth {
            return Err(ReorgRejection::DepthExceeded {
                depth: reorg_depth,
                max: self.max_depth,
            });
        }

        // 2. Economic finality — if the old chain segment has enough cumulative
        //    work, those blocks are considered economically final.
        if old_work.exceeds_finality() {
            return Err(ReorgRejection::ExceedsFinality { depth: reorg_depth });
        }

        // 3. Work comparison — the new chain must have at least
        //    MIN_WORK_RATIO × old_work total difficulty (integer math only).
        let required = (old_work.total_difficulty as u128 * MIN_WORK_RATIO_NUM as u128
            / MIN_WORK_RATIO_DEN as u128) as u64;
        if new_work.total_difficulty < required {
            return Err(ReorgRejection::InsufficientWork {
                old: old_work.total_difficulty,
                new: new_work.total_difficulty,
            });
        }

        // 4. Deterministic tiebreaker for equal-work chains (issue #42):
        //    lower tip hash wins, preventing deadlock between nodes seeing
        //    different orderings. This is an intentional string comparison —
        //    it is safe and deterministic because all block hashes use the
        //    same lowercase hex encoding, so lexicographic order on strings
        //    is consistent across all nodes.
        if new_work.total_difficulty == old_work.total_difficulty
            && new_tip_hash >= old_tip_hash
        {
            return Err(ReorgRejection::InsufficientWork {
                old: old_work.total_difficulty,
                new: new_work.total_difficulty,
            });
        }

        Ok(())
    }

    /// Like `detect`, but also validates economic/work-based reorg protection.
    ///
    /// `old_difficulties` and `new_difficulties` are the per-block difficulty
    /// values for each chain, aligned with the chain hash slices (i.e.
    /// `old_difficulties[i]` is the difficulty of `old_chain[i]`).
    pub fn detect_with_work(
        &mut self,
        old_chain: &[String],
        new_chain: &[String],
        old_difficulties: &[u64],
        new_difficulties: &[u64],
    ) -> Result<ReorgResult, ReorgRejection> {
        // First run the structural detection
        let result = self.detect(old_chain, new_chain);

        match &result {
            ReorgResult::Extended(_) => {
                // Chain extension (no fork) — no economic validation needed
                Ok(result)
            }
            ReorgResult::Reorged(event) => {
                let depth = event.depth;

                // Slice difficulties for the removed/added segments.
                // The removed blocks start after the common ancestor in old_chain.
                // old_chain length - blocks_removed.len() gives the ancestor+1 index.
                let old_ancestor_end = old_chain.len().saturating_sub(event.blocks_removed.len());
                let new_ancestor_end = new_chain.len().saturating_sub(event.blocks_added.len());

                let old_work = if old_ancestor_end < old_difficulties.len() {
                    CumulativeWork::from_difficulties(&old_difficulties[old_ancestor_end..])
                } else {
                    slog_warn!("reorg", "difficulty_length_mismatch",
                        chain_len => old_chain.len(),
                        diff_len => old_difficulties.len(),
                        ancestor_end => old_ancestor_end
                    );
                    CumulativeWork::from_difficulties(&[])
                };

                let new_work = if new_ancestor_end < new_difficulties.len() {
                    CumulativeWork::from_difficulties(&new_difficulties[new_ancestor_end..])
                } else {
                    slog_warn!("reorg", "difficulty_length_mismatch",
                        chain_len => new_chain.len(),
                        diff_len => new_difficulties.len(),
                        ancestor_end => new_ancestor_end
                    );
                    CumulativeWork::from_difficulties(&[])
                };

                self.validate_economic(
                    &old_work,
                    &new_work,
                    depth,
                    &event.old_tip,
                    &event.new_tip,
                )?;

                Ok(result)
            }
            ReorgResult::TooDeep => {
                // Already rejected by depth — surface as our typed error
                Err(ReorgRejection::DepthExceeded {
                    depth: self.max_depth + 1,
                    max: self.max_depth,
                })
            }
            ReorgResult::NoReorg => Ok(result),
        }
    }

    pub fn apply_plan(event: &ReorgEvent) -> ReorgPlan {
        ReorgPlan {
            rollback: event.blocks_removed.iter().rev().cloned().collect(),
            apply:    event.blocks_added.clone(),
        }
    }

    #[inline(always)]
    pub fn was_reorged(&self) -> bool {
        self.reorg_count > 0
    }

    #[inline(always)]
    pub fn last_depth(&self) -> u64 {
        self.last_reorg.as_ref().map(|r| r.depth).unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct ReorgPlan {
    pub rollback: Vec<String>,
    pub apply:    Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(blocks: &[&str]) -> Vec<String> {
        blocks.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_reorg_same_tip() {
        let mut mgr = ReorgManager::new();
        let c = chain(&["g", "b1", "b2"]);
        assert_eq!(mgr.detect(&c, &c), ReorgResult::NoReorg);
    }

    #[test]
    fn detects_simple_reorg() {
        let mut mgr = ReorgManager::new();

        let old = chain(&["g", "b1", "b2_old"]);
        let new = chain(&["g", "b1", "b2_new"]);

        match mgr.detect(&old, &new) {
            ReorgResult::Reorged(e) => {
                assert_eq!(e.common_ancestor, "b1");
                assert_eq!(e.depth, 1);
                assert_eq!(e.blocks_removed, vec!["b2_old"]);
                assert_eq!(e.blocks_added,   vec!["b2_new"]);
            }
            _ => panic!("expected reorg"),
        }
    }

    #[test]
    fn too_deep_reorg_rejected() {
        let mut mgr = ReorgManager::new();
        mgr.max_depth = 2;

        let old: Vec<String> = (0..10).map(|i| format!("old_{}", i)).collect();

        let mut new_chain = vec!["old_0".to_string()];
        new_chain.extend((0..8).map(|i| format!("new_{}", i)));

        assert_eq!(mgr.detect(&old, &new_chain), ReorgResult::TooDeep);
    }

    #[test]
    fn apply_plan_reverses_rollback() {
        let event = ReorgEvent {
            old_tip:         "b2".into(),
            new_tip:         "b2n".into(),
            common_ancestor: "b1".into(),
            depth:           1,
            blocks_removed:  vec!["b2".into()],
            blocks_added:    vec!["b2n".into()],
        };

        let plan = ReorgManager::apply_plan(&event);

        assert_eq!(plan.rollback, vec!["b2"]);
        assert_eq!(plan.apply,    vec!["b2n"]);
    }

    #[test]
    fn finality_depth_equals_max_reorg() {
        // FINALITY_DEPTH and MAX_REORG_DEPTH (in FullNode) should be consistent.
        // FINALITY_DEPTH defines when blocks become irreversible.
        assert!(FINALITY_DEPTH <= MAX_REORG_DEPTH,
            "FINALITY_DEPTH ({}) must not exceed MAX_REORG_DEPTH ({})",
            FINALITY_DEPTH, MAX_REORG_DEPTH);
        assert!(FINALITY_DEPTH >= 100,
            "FINALITY_DEPTH ({}) too low — minimum 100 for DAG safety",
            FINALITY_DEPTH);
    }

    #[test]
    fn economic_reorg_rejected_if_less_work() {
        let mut mgr = ReorgManager::new();

        let old = chain(&["g", "b1", "b2_old"]);
        let new = chain(&["g", "b1", "b2_new"]);

        // Old chain block has difficulty 100, new chain block has difficulty 50
        let old_diff = vec![1, 1, 100];
        let new_diff = vec![1, 1, 50];

        let result = mgr.detect_with_work(&old, &new, &old_diff, &new_diff);
        assert!(result.is_err());
        match result.unwrap_err() {
            ReorgRejection::InsufficientWork { old, new } => {
                assert_eq!(old, 100);
                assert_eq!(new, 50);
            }
            other => panic!("expected InsufficientWork, got {:?}", other),
        }
    }

    #[test]
    fn economic_reorg_accepted_if_more_work() {
        let mut mgr = ReorgManager::new();

        let old = chain(&["g", "b1", "b2_old"]);
        let new = chain(&["g", "b1", "b2_new"]);

        // New chain block has more difficulty
        let old_diff = vec![1, 1, 50];
        let new_diff = vec![1, 1, 100];

        let result = mgr.detect_with_work(&old, &new, &old_diff, &new_diff);
        assert!(result.is_ok());
        match result.unwrap() {
            ReorgResult::Reorged(e) => {
                assert_eq!(e.common_ancestor, "b1");
                assert_eq!(e.depth, 1);
            }
            other => panic!("expected Reorged, got {:?}", other),
        }
    }

    #[test]
    fn equal_work_tiebreaker_lower_hash_wins() {
        let mut mgr = ReorgManager::new();

        // "aaa_new" < "zzz_old" lexicographically, so the new chain should win
        let old = chain(&["g", "b1", "zzz_old"]);
        let new = chain(&["g", "b1", "aaa_new"]);

        let old_diff = vec![1, 1, 100];
        let new_diff = vec![1, 1, 100]; // equal work

        let result = mgr.detect_with_work(&old, &new, &old_diff, &new_diff);
        assert!(result.is_ok(), "lower-hash new tip should win the tiebreaker");
        match result.unwrap() {
            ReorgResult::Reorged(e) => {
                assert_eq!(e.new_tip, "aaa_new");
            }
            other => panic!("expected Reorged, got {:?}", other),
        }
    }

    #[test]
    fn equal_work_tiebreaker_higher_hash_rejected() {
        let mut mgr = ReorgManager::new();

        // "zzz_new" > "aaa_old" lexicographically, so the new chain should lose
        let old = chain(&["g", "b1", "aaa_old"]);
        let new = chain(&["g", "b1", "zzz_new"]);

        let old_diff = vec![1, 1, 100];
        let new_diff = vec![1, 1, 100]; // equal work

        let result = mgr.detect_with_work(&old, &new, &old_diff, &new_diff);
        assert!(result.is_err(), "higher-hash new tip should lose the tiebreaker");
        match result.unwrap_err() {
            ReorgRejection::InsufficientWork { .. } => {} // expected
            other => panic!("expected InsufficientWork, got {:?}", other),
        }
    }

    #[test]
    fn equal_work_same_hash_no_reorg() {
        // If somehow both tips have the same hash representation, keep current chain
        let mut mgr = ReorgManager::new();

        let old = chain(&["g", "b1", "same_tip"]);
        let new = chain(&["g", "b1", "same_tip"]);

        // Same tip => NoReorg from detect() itself (before economic check)
        let old_diff = vec![1, 1, 100];
        let new_diff = vec![1, 1, 100];

        let result = mgr.detect_with_work(&old, &new, &old_diff, &new_diff);
        assert!(result.is_ok());
        match result.unwrap() {
            ReorgResult::NoReorg => {} // expected — same tip means no reorg
            other => panic!("expected NoReorg, got {:?}", other),
        }
    }

    #[test]
    fn finality_prevents_deep_reorg() {
        let mut mgr = ReorgManager::new();

        // Build chains that diverge after genesis, with old chain having
        // enough cumulative work to be economically final.
        let old = chain(&["g", "b1", "b2_old", "b3_old"]);
        let new = chain(&["g", "b1", "b2_new", "b3_new"]);

        // Old removed segment (b2_old, b3_old) has total difficulty >= ECONOMIC_FINALITY_WORK
        let old_diff = vec![1, 1, 5_000, 5_000]; // removed segment sums to 10_000
        let new_diff = vec![1, 1, 6_000, 6_000]; // even more work, but old is final

        let result = mgr.detect_with_work(&old, &new, &old_diff, &new_diff);
        assert!(result.is_err());
        match result.unwrap_err() {
            ReorgRejection::ExceedsFinality { depth } => {
                assert_eq!(depth, 2);
            }
            other => panic!("expected ExceedsFinality, got {:?}", other),
        }
    }

    #[test]
    fn cumulative_work_calculation() {
        let work = CumulativeWork::from_difficulties(&[10, 20, 30, 40]);
        assert_eq!(work.total_difficulty, 100);
        assert_eq!(work.block_count, 4);
        assert!(!work.exceeds_finality()); // 100 < 10_000

        let big_work = CumulativeWork::from_difficulties(&[5_000, 5_000]);
        assert_eq!(big_work.total_difficulty, 10_000);
        assert_eq!(big_work.block_count, 2);
        assert!(big_work.exceeds_finality()); // 10_000 >= 10_000

        let empty = CumulativeWork::from_difficulties(&[]);
        assert_eq!(empty.total_difficulty, 0);
        assert_eq!(empty.block_count, 0);
        assert!(!empty.exceeds_finality());
    }

    #[test]
    fn reorg_count_increments() {
        let mut mgr = ReorgManager::new();

        let old = chain(&["g", "b1", "old_tip"]);
        let new = chain(&["g", "b1", "new_tip"]);

        mgr.detect(&old, &new);

        assert_eq!(mgr.reorg_count, 1);
    }
}