// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

pub mod zero_conf_guard;
pub mod confirmed_tx_store;

use rocksdb::{DB, Options, WriteBatch, ReadOptions};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use crate::errors::StorageError;

pub const LOCK_TTL_SECS:    u64 = 10_800;
pub const MAX_LOCKS_PER_TX: usize = 50;
pub const EVICT_BATCH_SIZE: usize = 1_000;

const PFX_LOCK:  &[u8] = b"l:";
const PFX_SPENT: &[u8] = b"s:";

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoRef {
    pub txid:  [u8; 32],
    pub index: u32,
}

impl UtxoRef {
    /// Strict construction — returns `None` if txid is not exactly 64 hex chars.
    ///
    /// CONSENSUS CRITICAL: rejects malformed txids instead of zero-padding.
    pub fn try_new(txid: &str, index: u32) -> Option<Self> {
        let bytes = crate::domain::types::hash::parse_hash256(txid).ok()?;
        Some(Self { txid: bytes, index })
    }

    /// Construct from pre-validated 32-byte hash (e.g. from UtxoKey).
    #[inline]
    pub fn from_bytes(txid: [u8; 32], index: u32) -> Self {
        Self { txid, index }
    }

    /// Legacy constructor — panics on bad input.  Test-only.
    #[cfg(test)]
    pub fn new(txid: &str, index: u32) -> Self {
        Self::try_new(txid, index).unwrap_or_else(|| {
            panic!("UtxoRef::new: invalid txid '{}' (must be 64 hex chars)", txid)
        })
    }

    #[inline]
    pub fn key(&self) -> [u8; 36] {
        let mut k = [0u8; 36];
        k[..32].copy_from_slice(&self.txid);
        k[32..].copy_from_slice(&self.index.to_le_bytes());
        k
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockRecord {
    pub locked_by:  Vec<u8>,
    pub locked_at:  u64,
    pub fee:        u64,
}

impl LockRecord {
    #[inline]
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.locked_at) > LOCK_TTL_SECS
    }
}

pub struct DoubleSpendProtector {
    db: Arc<DB>,
    read_opts: ReadOptions,
}

impl DoubleSpendProtector {

    pub fn new(path: &str) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.increase_parallelism(4);

        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| StorageError::OpenFailed { path: path.to_string(), reason: e.to_string() })?;

        let mut read_opts = ReadOptions::default();
        read_opts.fill_cache(false);

        Ok(Self {
            db: Arc::new(db),
            read_opts,
        })
    }

    pub fn open_default() -> Result<Self, StorageError> {
        let dsp_path = crate::config::node::node_config::NetworkMode::base_data_dir().join("dsp");
        match Self::new(&dsp_path.to_string_lossy()) {
            Ok(dsp) => Ok(dsp),
            Err(e) => {
                eprintln!("[DSP] WARNING: cannot open default DSP store: {}", e);
                let fallback = std::env::temp_dir().join(format!("shadowdag_dsp_{}", std::process::id()));
                Self::new(&fallback.to_string_lossy()).map_err(|e2| {
                    eprintln!("[DSP] ERROR: fallback DSP also failed: {}", e2);
                    e2
                })
            }
        }
    }

    #[inline]
    fn build_key(buf: &mut Vec<u8>, prefix: &[u8], suffix: &[u8; 36]) {
        buf.clear();
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(suffix);
    }

    // ─────────────────────────────────────────
    pub fn lock_inputs(
        &self,
        txid: &str,
        inputs: &[UtxoRef],
        fee: u64,
    ) -> Result<(), StorageError> {

        if inputs.len() > MAX_LOCKS_PER_TX {
            return Err(StorageError::Other("too many inputs".to_string()));
        }

        let txid_bytes = txid.as_bytes();
        let now = unix_now();

        let mut key = Vec::with_capacity(38);

        // 🔴 VALIDATION
        for utxo in inputs {

            let suffix = utxo.key();

            // LOCK CHECK
            Self::build_key(&mut key, PFX_LOCK, &suffix);

            if let Ok(Some(data)) = self.db.get_opt(&key, &self.read_opts) {
                if let Ok(rec) = bincode::deserialize::<LockRecord>(&data) {

                    if rec.locked_by == txid_bytes {
                        continue;
                    }

                    if rec.is_expired(now) {
                        // 🧹 cleanup expired lock
                        let _ = self.db.delete(&key);
                    } else if fee <= rec.fee {
                        return Err(StorageError::Other("locked by higher fee".to_string()));
                    }
                }
            }

            // SPENT CHECK
            Self::build_key(&mut key, PFX_SPENT, &suffix);

            if let Ok(Some(_)) = self.db.get_opt(&key, &self.read_opts) {
                return Err(StorageError::Other("already spent".to_string()));
            }
        }

        // 🟢 WRITE (with re-check)
        let mut batch = WriteBatch::default();
        let mut val_buf = Vec::with_capacity(64);

        for utxo in inputs {

            let suffix = utxo.key();

            // 🔁 RE-CHECK LOCK (race protection)
            Self::build_key(&mut key, PFX_LOCK, &suffix);

            if let Ok(Some(data)) = self.db.get_opt(&key, &self.read_opts) {
                if let Ok(rec) = bincode::deserialize::<LockRecord>(&data) {
                    if !rec.is_expired(now) && rec.locked_by != txid_bytes && fee <= rec.fee {
                        return Err(StorageError::Other("race: lock taken".to_string()));
                    }
                }
            }

            let rec = LockRecord {
                locked_by: txid_bytes.to_vec(),
                locked_at: now,
                fee,
            };

            val_buf.clear();
            if bincode::serialize_into(&mut val_buf, &rec).is_err() {
                return Err(StorageError::Serialization("serialization failed".to_string()));
            }

            batch.put(&key, &val_buf);
        }

        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    // ─────────────────────────────────────────
    pub fn release_locks(&self, inputs: &[UtxoRef]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        let mut key = Vec::with_capacity(38);

        for utxo in inputs {
            Self::build_key(&mut key, PFX_LOCK, &utxo.key());
            batch.delete(&key);
        }

        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    // ─────────────────────────────────────────
    pub fn confirm_spent(
        &self,
        inputs: &[UtxoRef],
        block_hash: &str,
    ) -> Result<(), StorageError> {

        let mut batch = WriteBatch::default();
        let mut key = Vec::with_capacity(38);

        for utxo in inputs {

            let suffix = utxo.key();

            Self::build_key(&mut key, PFX_SPENT, &suffix);
            batch.put(&key, block_hash.as_bytes());

            Self::build_key(&mut key, PFX_LOCK, &suffix);
            batch.delete(&key);
        }

        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    // ─────────────────────────────────────────
    pub fn unconfirm_spent(&self, inputs: &[UtxoRef]) -> Result<(), StorageError> {
        let mut batch = WriteBatch::default();
        let mut key = Vec::with_capacity(38);

        for utxo in inputs {
            Self::build_key(&mut key, PFX_SPENT, &utxo.key());
            batch.delete(&key);
        }

        self.db.write(batch).map_err(|e| StorageError::WriteFailed(e.to_string()))
    }

    // ─────────────────────────────────────────
    pub fn can_spend(&self, utxo: &UtxoRef) -> SpendStatus {

        let now = unix_now();
        let mut key = Vec::with_capacity(38);

        let suffix = utxo.key();

        Self::build_key(&mut key, PFX_SPENT, &suffix);

        if let Ok(Some(_)) = self.db.get_opt(&key, &self.read_opts) {
            return SpendStatus::ConfirmedSpent;
        }

        Self::build_key(&mut key, PFX_LOCK, &suffix);

        if let Ok(Some(data)) = self.db.get_opt(&key, &self.read_opts) {
            if let Ok(rec) = bincode::deserialize::<LockRecord>(&data) {
                if !rec.is_expired(now) {
                    return SpendStatus::LockedInMempool(
                        String::from_utf8_lossy(&rec.locked_by).to_string()
                    );
                }
            }
        }

        SpendStatus::Free
    }

    // ─────────────────────────────────────────
    /// Find the first intra-block double-spend conflict among a set of transactions.
    pub fn find_intra_block_conflicts(
        &self,
        txs: &[(String, Vec<UtxoRef>)],
    ) -> Option<(String, String)> {
        let mut seen: std::collections::HashMap<[u8; 36], &str> =
            std::collections::HashMap::new();
        for (tx_id, inputs) in txs {
            for inp in inputs {
                let k = inp.key();
                if let Some(&prev) = seen.get(&k) {
                    return Some((prev.to_string(), tx_id.clone()));
                }
                seen.insert(k, tx_id);
            }
        }
        None
    }

    pub fn evict_expired_locks(&self) -> usize {
        let now = unix_now();

        let iter = self.db.prefix_iterator(PFX_LOCK);

        let mut batch = WriteBatch::default();
        let mut count = 0;

        for item in iter.take(EVICT_BATCH_SIZE) {
            let (k, v) = match item {
                Ok(kv) => kv,
                Err(_) => continue,
            };
            if let Ok(rec) = bincode::deserialize::<LockRecord>(&v) {
                if rec.is_expired(now) {
                    batch.delete(&*k);
                    count += 1;
                }
            }
        }

        if count > 0 {
            let _ = self.db.write(batch);
        }

        count
    }
}

// ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum SpendStatus {
    Free,
    LockedInMempool(String),
    ConfirmedSpent,
}

#[inline]
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(l: &str) -> String { format!("/tmp/dsp_{}", l) }
    fn dsp(l: &str) -> DoubleSpendProtector {
        let p = tmp(l);
        let _ = fs::remove_dir_all(&p);
        DoubleSpendProtector::new(&p).unwrap()
    }
    /// Generate a deterministic 64-char hex hash from a short label.
    fn test_hash(label: &str) -> String {
        use sha2::{Sha256, Digest};
        hex::encode(Sha256::digest(label.as_bytes()))
    }
    fn utxo(label: &str, idx: u32) -> UtxoRef {
        UtxoRef::new(&test_hash(label), idx)
    }

    #[test]
    fn lock_and_release() {
        let d = dsp("lock");
        let inputs = vec![utxo("tx1", 0), utxo("tx1", 1)];
        assert!(d.lock_inputs("spender1", &inputs, 100).is_ok());
        assert!(matches!(d.can_spend(&utxo("tx1", 0)), SpendStatus::LockedInMempool(_)));
        assert!(d.release_locks(&inputs).is_ok());
        assert_eq!(d.can_spend(&utxo("tx1", 0)), SpendStatus::Free);
    }

    #[test]
    fn double_spend_detected() {
        let d = dsp("ds");
        let inputs = vec![utxo("tx2", 0)];
        assert!(d.lock_inputs("txA", &inputs, 100).is_ok());

        let err = d.lock_inputs("txB", &inputs, 50);
        assert!(err.is_err());
    }

    #[test]
    fn rbf_higher_fee_wins() {
        let d = dsp("rbf");
        let inputs = vec![utxo("tx3", 0)];
        assert!(d.lock_inputs("txA", &inputs, 100).is_ok());

        assert!(d.lock_inputs("txB", &inputs, 500).is_ok());

        assert!(matches!(d.can_spend(&utxo("tx3", 0)), SpendStatus::LockedInMempool(ref t) if t == "txB"));
    }

    #[test]
    fn confirmed_spent_blocks_reuse() {
        let d = dsp("confirmed");
        let inputs = vec![utxo("tx4", 0)];
        assert!(d.confirm_spent(&inputs, "block123").is_ok());
        assert_eq!(d.can_spend(&utxo("tx4", 0)), SpendStatus::ConfirmedSpent);
        assert!(d.lock_inputs("txC", &inputs, 100).is_err());
    }

    #[test]
    fn intra_block_conflict() {
        let d = dsp("intra");
        let txs = vec![
            ("txA".to_string(), vec![utxo("base", 0), utxo("base", 1)]),
            ("txB".to_string(), vec![utxo("base", 0)]),
        ];
        let conflict = d.find_intra_block_conflicts(&txs);
        assert!(conflict.is_some());
    }

    #[test]
    fn rollback_unconfirm() {
        let d = dsp("rollback");
        let inputs = vec![utxo("tx5", 0)];
        assert!(d.confirm_spent(&inputs, "blockX").is_ok());
        assert!(d.unconfirm_spent(&inputs).is_ok());
        assert_eq!(d.can_spend(&utxo("tx5", 0)), SpendStatus::Free);
    }

    #[test]
    fn try_new_rejects_short_txid() {
        assert!(UtxoRef::try_new("aabb", 0).is_none());
    }

    #[test]
    fn try_new_rejects_non_hex() {
        assert!(UtxoRef::try_new("zz".repeat(32).as_str(), 0).is_none());
    }

    #[test]
    fn try_new_accepts_valid() {
        let valid = "aa".repeat(32);
        assert!(UtxoRef::try_new(&valid, 42).is_some());
    }
}
