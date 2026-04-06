// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::genesis::genesis::genesis_hash;

#[derive(Debug, Clone)]
pub struct CheckpointEntry {
    pub height: u64,
    pub hash:   String,
}

impl CheckpointEntry {
    fn new(height: u64, hash: String) -> Self {
        Self { height, hash }
    }
}

pub struct Checkpoints;

impl Checkpoints {
    pub fn all() -> Vec<CheckpointEntry> {
        vec![
            CheckpointEntry::new(0, genesis_hash()),
        ]
    }

    pub fn is_valid(height: u64, hash: &str) -> bool {
        for cp in Self::all() {
            if cp.height == height {
                return cp.hash.eq_ignore_ascii_case(hash);
            }
        }
        true
    }

    pub fn last_checkpoint() -> Option<CheckpointEntry> {
        Self::all().last().cloned()
    }

    pub fn before_last_checkpoint(height: u64) -> bool {
        match Self::last_checkpoint() {
            Some(cp) => height <= cp.height,
            None => false,
        }
    }

    pub fn count() -> usize {
        Self::all().len()
    }

    pub fn get(height: u64) -> Option<CheckpointEntry> {
        Self::all().into_iter().find(|cp| cp.height == height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::genesis::genesis::genesis_hash;

    #[test]
    fn genesis_checkpoint_is_valid() {
        let g = genesis_hash();
        assert!(Checkpoints::is_valid(0, &g));
    }

    #[test]
    fn wrong_genesis_hash_rejected() {
        assert!(!Checkpoints::is_valid(0, "deadbeef"));
    }

    #[test]
    fn unknown_height_always_valid() {
        assert!(Checkpoints::is_valid(99_999, "any_hash_is_fine_here"));
    }

    #[test]
    fn last_checkpoint_returns_genesis() {
        let cp = Checkpoints::last_checkpoint().expect("must have at least genesis");
        assert_eq!(cp.height, 0);
        assert_eq!(cp.hash, genesis_hash());
    }

    #[test]
    fn before_last_checkpoint_works() {
        assert!(Checkpoints::before_last_checkpoint(0));
        assert!(!Checkpoints::before_last_checkpoint(1));
    }

    #[test]
    fn checkpoint_count_correct() {
        assert!(Checkpoints::count() >= 1, "At least genesis checkpoint must exist");
    }
}
