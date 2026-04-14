// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::genesis::genesis::genesis_hash;

#[derive(Debug, Clone)]
pub struct CheckpointEntry {
    pub height: u64,
    pub hash: String,
}

impl CheckpointEntry {
    pub fn new(height: u64, hash: String) -> Self {
        Self { height, hash }
    }
}

pub struct Checkpoints;

impl Checkpoints {
    pub fn all() -> Vec<CheckpointEntry> {
        vec![CheckpointEntry::new(0, genesis_hash())]
    }

    /// Check if a block hash is valid at the given height against HARDCODED
    /// checkpoints only.  For validation that also considers dynamic
    /// (auto-generated) checkpoints stored in RocksDB, use
    /// [`is_valid_with_dynamic`](Self::is_valid_with_dynamic).
    pub fn is_valid(height: u64, hash: &str) -> bool {
        for cp in Self::all() {
            if cp.height == height {
                return cp.hash.eq_ignore_ascii_case(hash);
            }
        }
        true
    }

    /// Check if a block hash is valid at the given height against BOTH
    /// hardcoded and dynamic (auto-generated) checkpoints from RocksDB.
    pub fn is_valid_with_dynamic(height: u64, hash: &str, db: &rocksdb::DB) -> bool {
        // Check hardcoded first
        for cp in Self::all() {
            if cp.height == height && !cp.hash.eq_ignore_ascii_case(hash) {
                return false;
            }
        }
        // Check dynamic checkpoints from DB
        for cp in Self::all_with_dynamic(db) {
            if cp.height == height && !cp.hash.eq_ignore_ascii_case(hash) {
                return false;
            }
        }
        true
    }

    /// Returns the last HARDCODED checkpoint.
    /// For the most recent checkpoint including auto-generated ones,
    /// use `all_with_dynamic(db)` and take the last entry.
    pub fn last_checkpoint() -> Option<CheckpointEntry> {
        Self::all().last().cloned()
    }

    /// Returns true if `height` is at or before the last HARDCODED checkpoint.
    /// For the most recent checkpoint including auto-generated ones,
    /// use `all_with_dynamic(db)` and take the last entry.
    pub fn before_last_checkpoint(height: u64) -> bool {
        match Self::last_checkpoint() {
            Some(cp) => height <= cp.height,
            None => false,
        }
    }

    /// Returns the number of HARDCODED checkpoints.
    /// For the total count including auto-generated ones,
    /// use `all_with_dynamic(db).len()`.
    pub fn count() -> usize {
        Self::all().len()
    }

    /// Returns a HARDCODED checkpoint at the given height, if one exists.
    /// For checkpoints including auto-generated ones,
    /// use `all_with_dynamic(db)` and search the result.
    pub fn get(height: u64) -> Option<CheckpointEntry> {
        Self::all().into_iter().find(|cp| cp.height == height)
    }

    /// Load dynamic (auto-generated) checkpoints from a RocksDB instance
    /// and merge them with the hardcoded checkpoints.
    pub fn all_with_dynamic(db: &rocksdb::DB) -> Vec<CheckpointEntry> {
        // Auto-checkpoints use the same key format as FinalityManager
        // (see engine::consensus::finality::AutoCheckpoint)
        let mut all = Self::all(); // hardcoded first

        // Load auto-checkpoints from DB
        let prefix = b"chkpt:";
        let iter = db.prefix_iterator(prefix);
        for item in iter {
            let (key, value) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if key.len() < prefix.len() + 8 || !key.starts_with(prefix) {
                break;
            }
            let height_bytes: [u8; 8] = match key[prefix.len()..prefix.len() + 8].try_into() {
                Ok(b) => b,
                Err(_) => continue,
            };
            let height = u64::from_be_bytes(height_bytes);
            let hash = String::from_utf8_lossy(&value).to_string();

            // Don't duplicate heights
            if !all.iter().any(|cp| cp.height == height) {
                all.push(CheckpointEntry { height, hash });
            }
        }

        all.sort_by_key(|cp| cp.height);
        all
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
        assert!(
            Checkpoints::count() >= 1,
            "At least genesis checkpoint must exist"
        );
    }
}
