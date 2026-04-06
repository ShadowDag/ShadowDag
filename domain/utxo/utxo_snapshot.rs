// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};

use crate::domain::utxo::utxo_set::{UtxoSet, utxo_key};
use crate::errors::StorageError;
use crate::slog_warn;

pub const SNAPSHOT_INTERVAL: u64 = 1_000;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UtxoEntry {
    pub key:     String,
    pub owner:   String,
    pub amount:  u64,
    pub address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SnapshotMeta {
    pub height:  u64,
    pub entries: Vec<UtxoEntry>,
}

/// Abstract snapshot persistence.
///
/// domain/ defines this trait; infrastructure/ implements it.
pub trait SnapshotStore: Send + Sync {
    fn save_snapshot(&self, meta: &SnapshotMeta) -> Result<(), StorageError>;
    fn load_snapshot(&self, height: u64) -> Option<SnapshotMeta>;
    fn load_latest_snapshot(&self) -> Option<SnapshotMeta>;
}

pub struct UtxoSnapshot;

impl UtxoSnapshot {
    pub fn should_snapshot(height: u64) -> bool {
        height > 0 && height.is_multiple_of(SNAPSHOT_INTERVAL)
    }

    pub fn export(utxo_set: &UtxoSet) -> Vec<UtxoEntry> {
        utxo_set.export_all()
            .into_iter()
            .map(|(key, utxo)| UtxoEntry {
                key: key.to_string(),
                owner:   utxo.owner,
                amount:  utxo.amount,
                address: utxo.address,
            })
            .collect()
    }

    pub fn save(
        utxo_set: &UtxoSet,
        store:    &dyn SnapshotStore,
        height:   u64,
    ) -> Result<(), StorageError> {
        let entries = Self::export(utxo_set);
        let meta    = SnapshotMeta { height, entries };
        store.save_snapshot(&meta)
    }

    pub fn load(store: &dyn SnapshotStore, height: u64) -> Option<SnapshotMeta> {
        store.load_snapshot(height)
    }

    pub fn load_latest(store: &dyn SnapshotStore) -> Option<SnapshotMeta> {
        store.load_latest_snapshot()
    }

    /// Apply snapshot entries to the UTXO set.
    /// Returns the number of entries that failed to apply.
    /// Logs a warning for each malformed key but continues processing
    /// so that valid entries are still restored.
    pub fn apply(entries: &[UtxoEntry], utxo_set: &UtxoSet) -> Result<(), StorageError> {
        // Pass 1: validate all keys before modifying any state
        let mut parsed = Vec::with_capacity(entries.len());
        let mut validation_errors = Vec::new();

        for (i, entry) in entries.iter().enumerate() {
            let result = (|| -> Result<_, StorageError> {
                if entry.amount == 0 {
                    return Err(StorageError::Other(format!("zero amount for key '{}'", entry.key)));
                }
                let (hash, idx_s) = entry.key.rsplit_once(':')
                    .ok_or_else(|| StorageError::Other(format!("missing ':' separator in key '{}'", entry.key)))?;
                let idx: u32 = idx_s.parse()
                    .map_err(|e| StorageError::Other(format!("invalid index '{}' in key '{}': {}", idx_s, entry.key, e)))?;
                let k = utxo_key(hash, idx)
                    .map_err(|e| StorageError::Other(format!("utxo_key failed for '{}': {}", entry.key, e)))?;
                Ok((k, entry))
            })();

            match result {
                Ok(pair) => parsed.push(pair),
                Err(reason) => {
                    slog_warn!("utxo", "malformed_snapshot_entry", index => &i.to_string(), total => &entries.len().to_string(), reason => &reason);
                    validation_errors.push(reason);
                }
            }
        }

        if !validation_errors.is_empty() {
            return Err(StorageError::Other(format!(
                "snapshot apply aborted: {}/{} entries failed validation — no state modified",
                validation_errors.len(), entries.len()
            )));
        }

        // Pass 2: all keys validated — safe to apply
        for (k, entry) in &parsed {
            utxo_set.add_utxo(k, entry.owner.clone(), entry.amount, entry.address.clone());
        }

        Ok(())
    }

    pub fn validate(entries: &[UtxoEntry]) -> bool {
        for entry in entries {
            if entry.key.is_empty() {
                return false;
            }
            if entry.amount == 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocksdb::{DB, Options};


    const PFX_SNAPSHOT: &str = "snapshot:";

    fn make_db() -> DB {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = format!("/tmp/test_snapshot_{}", ts);
        let mut opts = Options::default();
        opts.create_if_missing(true);
        DB::open(&opts, &path).expect("test DB open failed")
    }

    fn make_entries(n: usize) -> Vec<UtxoEntry> {
        (0..n).map(|i| UtxoEntry {
            key:     format!("key:{}", i),
            owner:   format!("owner{}", i),
            amount:  (i as u64 + 1) * 100,
            address: format!("addr{}", i),
        }).collect()
    }

    /// Test-only SnapshotStore backed by rocksdb for round-trip tests
    struct TestSnapshotStore {
        db: DB,
    }

    impl TestSnapshotStore {
        fn new(db: DB) -> Self { Self { db } }

        fn snapshot_key(height: u64) -> String {
            format!("{}{}", PFX_SNAPSHOT, hex::encode(height.to_be_bytes()))
        }
    }

    impl SnapshotStore for TestSnapshotStore {
        fn save_snapshot(&self, meta: &SnapshotMeta) -> Result<(), StorageError> {
            let bytes = bincode::serialize(meta)
                .map_err(|e| StorageError::Serialization(format!("serialise: {}", e)))?;
            let key = Self::snapshot_key(meta.height);
            self.db.put(key.as_bytes(), &bytes)?;
            Ok(())
        }

        fn load_snapshot(&self, height: u64) -> Option<SnapshotMeta> {
            let key = Self::snapshot_key(height);
            match self.db.get(key.as_bytes()) {
                Ok(Some(data)) => bincode::deserialize::<SnapshotMeta>(&data).ok(),
                _ => None,
            }
        }

        fn load_latest_snapshot(&self) -> Option<SnapshotMeta> {
            let prefix = PFX_SNAPSHOT.as_bytes();
            let iter   = self.db.prefix_iterator(prefix);
            let mut best: Option<SnapshotMeta> = None;

            for item in iter {
                match item {
                    Ok((k, v)) => {
                        let k_str = String::from_utf8(k.to_vec()).unwrap_or_default();
                        if !k_str.starts_with(PFX_SNAPSHOT) { break; }
                        if let Ok(meta) = bincode::deserialize::<SnapshotMeta>(&v) {
                            let is_better = best.as_ref().is_none_or(|b| meta.height > b.height);
                            if is_better { best = Some(meta); }
                        }
                    }
                    Err(_) => break,
                }
            }
            best
        }
    }

    #[test]
    fn should_snapshot_at_interval() {
        assert!(!UtxoSnapshot::should_snapshot(0));
        assert!(!UtxoSnapshot::should_snapshot(999));
        assert!(UtxoSnapshot::should_snapshot(1_000));
        assert!(UtxoSnapshot::should_snapshot(2_000));
        assert!(!UtxoSnapshot::should_snapshot(1_001));
    }

    #[test]
    fn snapshot_key_sortable() {
        let k999  = format!("snapshot:{}", hex::encode(999u64.to_be_bytes()));
        let k1000 = format!("snapshot:{}", hex::encode(1000u64.to_be_bytes()));
        assert!(k999 < k1000);
    }

    #[test]
    fn validate_rejects_zero_amount() {
        let entries = vec![UtxoEntry {
            key:     "k".to_string(),
            owner:   "o".to_string(),
            amount:  0,
            address: "a".to_string(),
        }];
        assert!(!UtxoSnapshot::validate(&entries));
    }

    #[test]
    fn validate_rejects_empty_key() {
        let entries = vec![UtxoEntry {
            key:     String::new(),
            owner:   "o".to_string(),
            amount:  100,
            address: "a".to_string(),
        }];
        assert!(!UtxoSnapshot::validate(&entries));
    }

    #[test]
    fn validate_accepts_valid_entries() {
        let entries = make_entries(3);
        assert!(UtxoSnapshot::validate(&entries));
    }

    #[test]
    fn round_trip_serialisation() {
        let meta = SnapshotMeta {
            height:  1_000,
            entries: make_entries(5),
        };
        let bytes = bincode::serialize(&meta).unwrap();
        let restored: SnapshotMeta = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored.height, 1_000);
        assert_eq!(restored.entries.len(), 5);
    }

    #[test]
    fn apply_returns_error_on_malformed_keys() {
        // Valid key needs 64-char hex hash : u32 index
        let valid_hash = "a".repeat(64);
        let entries = vec![
            UtxoEntry { key: format!("{}:0", valid_hash), owner: "o".into(), amount: 100, address: "a".into() },
            UtxoEntry { key: "no_separator".into(), owner: "o".into(), amount: 100, address: "a".into() },
            UtxoEntry { key: "abc:notanumber".into(), owner: "o".into(), amount: 100, address: "a".into() },
        ];
        let utxo_set = UtxoSet::new_empty();
        let result = UtxoSnapshot::apply(&entries, &utxo_set);
        assert!(result.is_err(), "apply must return Err when entries have malformed keys");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("2/3 entries have invalid keys"), "should report 2 out of 3 invalid keys, got: {}", err_msg);
    }

    #[test]
    fn apply_succeeds_with_all_valid_keys() {
        let valid_hash = "b".repeat(64);
        let entries = vec![
            UtxoEntry { key: format!("{}:0", valid_hash), owner: "o1".into(), amount: 100, address: "a1".into() },
            UtxoEntry { key: format!("{}:1", valid_hash), owner: "o2".into(), amount: 200, address: "a2".into() },
        ];
        let utxo_set = UtxoSet::new_empty();
        let result = UtxoSnapshot::apply(&entries, &utxo_set);
        assert!(result.is_ok(), "apply must succeed when all keys are valid");
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let db = make_db();
        let store = TestSnapshotStore::new(db);
        assert!(UtxoSnapshot::load(&store, 9_999_999).is_none());
    }

    #[test]
    fn load_latest_empty_db_returns_none() {
        let db = make_db();
        let store = TestSnapshotStore::new(db);
        assert!(UtxoSnapshot::load_latest(&store).is_none());
    }
}
