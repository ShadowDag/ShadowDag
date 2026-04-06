// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Property-based tests for DAG operations and pruning invariants.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn pruning_selects_old_blocks(
            current_height in 500u64..10_000,
            depth in 100u64..500,
        ) {
            use crate::engine::pruning::PruningEngine;
            use std::collections::HashMap;
            let mut engine = PruningEngine::new(depth);
            let cutoff = current_height.saturating_sub(depth);
            let mut blocks = HashMap::new();
            blocks.insert("old".to_string(), cutoff.saturating_sub(1));
            blocks.insert("new".to_string(), current_height);
            let prunable = engine.select_prunable(&blocks, current_height);
            if cutoff > 1 {
                prop_assert!(prunable.contains(&"old".to_string()));
            }
            prop_assert!(!prunable.contains(&"new".to_string()));
        }

        #[test]
        fn snapshot_interval_consistent(height in 0u64..100_000_000) {
            use crate::engine::state_snapshot::SNAPSHOT_INTERVAL_BLOCKS;
            let should = height > 0 && height % SNAPSHOT_INTERVAL_BLOCKS == 0;
            if height > 0 && height % 10_000 == 0 {
                prop_assert!(should);
            }
        }

        #[test]
        fn blue_work_monotonic(d1 in 1u64..1_000_000, d2 in 1u64..1_000_000) {
            use crate::engine::consensus::difficulty::difficulty::Difficulty;
            let w1 = Difficulty::blue_work(d1);
            let w2 = Difficulty::blue_work(d2);
            if d1 > d2 {
                prop_assert!(w1 > w2);
            }
        }

        #[test]
        fn blue_work_accumulation(
            parent_work in 0u128..u128::MAX / 2,
            difficulty in 1u64..1_000_000,
        ) {
            use crate::engine::consensus::difficulty::difficulty::Difficulty;
            let new_work = Difficulty::accumulate_blue_work(parent_work, difficulty);
            prop_assert!(new_work >= parent_work);
            prop_assert_eq!(new_work, parent_work + difficulty as u128);
        }

        #[test]
        fn past_median_time_in_range(
            timestamps in prop::collection::vec(1_000_000u64..2_000_000_000, 3..20),
        ) {
            use crate::engine::consensus::difficulty::difficulty::Difficulty;
            let pmt = Difficulty::past_median_time(&timestamps);
            let min = *timestamps.iter().min().unwrap();
            let max = *timestamps.iter().max().unwrap();
            prop_assert!(pmt >= min && pmt <= max);
        }

        #[test]
        fn difficulty_window_sample_size_positive(height in 0u64..10_000_000) {
            use crate::engine::consensus::difficulty::difficulty_window::DifficultyWindow;
            let size = DifficultyWindow::sample_size(height);
            prop_assert!(size >= 10);
            prop_assert!(size <= 120);
        }
    }
}
