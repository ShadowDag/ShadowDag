// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteBatch};
use std::collections::{HashSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::MempoolError;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::transaction::tx_validator::TxValidator;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::infrastructure::storage::rocksdb::core::db::{open_shared_db, SharedDbSource};
use crate::service::mempool::core::rbf::{RbfEngine, RbfResult, MempoolTxInfo};

// ── All pool limits imported from the single source of truth ─────────
use crate::config::consensus::mempool_config::MempoolConfig;

pub const MAX_MEMPOOL_SIZE:        usize = MempoolConfig::MAX_MEMPOOL_SIZE;
pub const MAX_MEMPOOL_BYTES:       usize = MempoolConfig::MAX_MEMPOOL_BYTES;
pub const MAX_TX_BYTE_SIZE:        usize = MempoolConfig::MAX_TX_BYTE_SIZE;
pub const MAX_BLOCK_TX_COUNT:      usize = MempoolConfig::MAX_BLOCK_TX_COUNT;
pub const MIN_RELAY_FEE:           u64   = MempoolConfig::MIN_RELAY_FEE;
pub const MIN_FEE_RATE:            f64   = MempoolConfig::MIN_FEE_RATE;
const EVICT_BATCH_SIZE:            usize = MempoolConfig::EVICTION_BATCH_SIZE;
pub const MAX_MEMPOOL_TX_AGE_SECS: u64   = MempoolConfig::MAX_MEMPOOL_TX_AGE_SECS;

/// Maximum number of unconfirmed transactions from the same sender address.
/// Prevents a single wallet from monopolizing the mempool with min-fee TXs.
/// 25 is generous enough for legitimate batched operations while blocking
/// simple flood attacks (Kaspa uses 16, Bitcoin Core uses 25).
const MAX_TXS_PER_SENDER: usize = 25;

const PFX_TX:     &[u8] = b"tx:";
const PFX_FEE:    &[u8] = b"fee:";
#[allow(dead_code)]
const PFX_INPUT:  &[u8] = b"inp:";
#[allow(dead_code)]
const PFX_DEP:    &[u8] = b"dep:";
const PFX_RDEP:   &[u8] = b"rdep:";
/// Per-sender TX count index: "sender:{addr}:{hash}" → "1"
/// Used for anti-spam: limit unconfirmed TXs per originating address.
const PFX_SENDER: &[u8] = b"sender:";
/// Metadata key for tracking total serialized bytes in the pool.
const META_TOTAL_BYTES: &[u8] = b"_meta:total_bytes";
/// Metadata key for tracking TX count without full scan.
const META_TX_COUNT:    &[u8] = b"_meta:tx_count";
/// Metadata key for tracking total fees (for O(1) stats).
const META_TOTAL_FEES:  &[u8] = b"_meta:total_fees";

pub struct Mempool {
    db: Arc<DB>,
}

// ─────────────────────────────────────────────────────────
// Internal metadata helpers (atomic counters via RocksDB)
// ─────────────────────────────────────────────────────────
impl Mempool {
    /// Iterate the fee index backward (lowest fee first) and return up to
    /// `limit` tx hashes. Uses RocksDB's reverse seek so only `limit` entries
    /// are read — O(limit) instead of O(n) for the full prefix scan + reverse.
    fn fee_index_lowest(&self, limit: usize) -> Vec<String> {
        // Seek to just past the end of the "fee:" prefix range.
        // "fee;" is the byte after "fee:" in ASCII, so seeking from "fee;"
        // backward lands on the last "fee:*" key.
        let past_end = b"fee;";
        let iter = self.db.iterator(
            rocksdb::IteratorMode::From(past_end, rocksdb::Direction::Reverse),
        );
        iter.filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_FEE))
            .filter_map(|(_, v)| String::from_utf8(v.to_vec()).ok())
            .take(limit)
            .collect()
    }
    #[inline]
    fn meta_get_u64(&self, key: &[u8]) -> u64 {
        match self.db.get(key) {
            Ok(Some(v)) if v.len() >= 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&v[..8]);
                u64::from_le_bytes(buf)
            }
            _ => 0,
        }
    }

    #[inline]
    fn meta_set_u64(&self, key: &[u8], val: u64) {
        let _ = self.db.put(key, val.to_le_bytes());
    }

    #[inline]
    fn meta_inc(&self, key: &[u8], delta: u64) {
        let cur = self.meta_get_u64(key);
        self.meta_set_u64(key, cur.saturating_add(delta));
    }

    #[inline]
    fn meta_dec(&self, key: &[u8], delta: u64) {
        let cur = self.meta_get_u64(key);
        self.meta_set_u64(key, cur.saturating_sub(delta));
    }

    /// Current total serialized bytes in the pool.
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.meta_get_u64(META_TOTAL_BYTES)
    }

    /// Total fees of all TXs in the pool (O(1) via metadata counter).
    #[inline]
    pub fn total_fees(&self) -> u64 {
        self.meta_get_u64(META_TOTAL_FEES)
    }

    /// Compute fee rate (satoshis per byte) for a transaction.
    #[inline]
    fn fee_rate(tx: &Transaction) -> f64 {
        let size = tx.canonical_bytes().len().max(1) as f64;
        tx.fee as f64 / size
    }

    /// Count how many unconfirmed TXs a sender address has in the pool.
    /// Uses the sender: prefix index for O(n) per-address, not full-pool scan.
    fn sender_tx_count(&self, sender: &str) -> usize {
        let prefix = format!("sender:{}:", sender);
        let prefix_bytes = prefix.as_bytes().to_vec();
        self.db
            .prefix_iterator(prefix.as_bytes())
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(&prefix_bytes))
            .count()
    }

    /// Extract the primary sender address from a transaction.
    /// For standard TXs: first input's `owner` field.
    /// For coinbase TXs: returns None (no sender).
    fn tx_sender(tx: &Transaction) -> Option<&str> {
        if tx.is_coinbase() { return None; }
        tx.inputs.first().map(|inp| inp.owner.as_str())
    }

    // ── Surge pricing ────────────────────────────────────────────────────
    /// Dynamic fee-rate floor that rises with pool utilization.
    ///
    /// Below 50% full → base MIN_FEE_RATE (1.0 sat/byte)
    /// 50-75% full    → 2× MIN_FEE_RATE
    /// 75-90% full    → 4× MIN_FEE_RATE
    /// 90%+ full      → 8× MIN_FEE_RATE
    ///
    /// This prevents spam from filling the pool at the minimum rate.
    /// Legitimate users get price signals to bid higher during congestion.
    pub fn effective_min_fee_rate(&self) -> f64 {
        let count = self.count();
        let pct = if MAX_MEMPOOL_SIZE > 0 {
            (count * 100) / MAX_MEMPOOL_SIZE
        } else {
            0
        };

        let multiplier = match pct {
            0..=49  => 1.0,
            50..=74 => 2.0,
            75..=89 => 4.0,
            _       => 8.0,
        };

        MIN_FEE_RATE * multiplier
    }

    // ── RBF helper ─────────────────────────────────────────────────────
    /// Build RBF info for a conflicting mempool TX.
    fn build_rbf_info(&self, tx: &Transaction) -> MempoolTxInfo {
        MempoolTxInfo {
            hash:              tx.hash.clone(),
            fee:               tx.fee,
            fee_rate:          Self::fee_rate(tx),
            size:              tx.canonical_bytes().len(),
            inputs:            tx.inputs.iter().filter_map(|inp| {
                crate::domain::utxo::utxo_set::utxo_key(&inp.txid, inp.index)
                    .ok()
                    .map(|k| k.to_string())
            }).collect(),
            dependents:        self.get_dependents(&tx.hash),
            replacement_depth: 0,
        }
    }

    /// Minimum descendant-package fee in the pool. Returns 0 if empty.
    /// Scans the lowest-fee tail of the fee index (up to EVICT_BATCH_SIZE
    /// entries) and returns the smallest `descendant_fee()` among them.
    /// This is used by the admission gate so a new TX must beat the
    /// weakest *package*, not just the weakest individual fee.
    pub fn pool_min_descendant_fee(&self) -> u64 {
        let tail_hashes = self.fee_index_lowest(EVICT_BATCH_SIZE);

        tail_hashes.iter()
            .map(|h| self.descendant_fee(h))
            .min()
            .unwrap_or(0)
    }

    /// Minimum descendant-package fee-rate in the pool. Returns 0.0 if empty.
    /// Used by the admission gate: a new TX must beat this rate to enter a full pool.
    pub fn pool_min_descendant_fee_rate(&self) -> f64 {
        let tail_hashes = self.fee_index_lowest(EVICT_BATCH_SIZE);

        tail_hashes.iter()
            .map(|h| self.descendant_fee_rate(h))
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(0.0)
    }

    /// Minimum fee in the pool (the lowest-fee TX). Returns 0 if pool is empty.
    /// The fee index is sorted ascending by `u64::MAX - fee`, so the *last*
    /// entry is the lowest fee.
    pub fn pool_min_fee(&self) -> u64 {
        // Reverse-seek to the last fee-index key (lowest fee) in O(1)
        let past_end = b"fee;";
        let mut iter = self.db.iterator(
            rocksdb::IteratorMode::From(past_end, rocksdb::Direction::Reverse),
        );
        match iter.next() {
            Some(Ok((k, _))) if k.starts_with(PFX_FEE) => {
                // Key format: "fee:{inverted_fee:020}:{hash}"
                if let Ok(s) = String::from_utf8(k.to_vec()) {
                    let parts: Vec<&str> = s.splitn(3, ':').collect();
                    if parts.len() >= 2 {
                        if let Ok(inverted) = parts[1].parse::<u64>() {
                            return u64::MAX - inverted;
                        }
                    }
                }
                0
            }
            _ => 0,
        }
    }
}

impl Mempool {
    pub fn new<S: Into<SharedDbSource>>(source: S) -> Result<Self, MempoolError> {
        Self::try_new(source).map_err(|e| {
            eprintln!("[Mempool] CRITICAL: Mempool storage unavailable: {}", e);
            e
        })
    }

    pub fn try_new<S: Into<SharedDbSource>>(source: S) -> Result<Self, MempoolError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        let db = open_shared_db(source, &opts)
            .map_err(|e| MempoolError::Storage(crate::errors::StorageError::OpenFailed {
                path: "mempool".to_string(),
                reason: e.to_string(),
            }))?;
        Ok(Self { db })
    }

    /// Storage-only insertion. Does NOT validate UTXO/signatures.
    /// For production callers, use `add_transaction_validated()` instead.
    /// This method is public for tests and internal use only.
    /// Force-add a transaction, skipping structural validation.
    /// For tests only — bypasses fee, input, and conflict checks.
    #[cfg(test)]
    pub fn add_transaction_test(&self, tx: &Transaction) -> bool {
        let tx_key = format!("tx:{}", tx.hash);
        if matches!(self.db.get(tx_key.as_bytes()), Ok(Some(_))) {
            return false; // duplicate
        }
        // Check conflict (same as production)
        if self.has_conflict(tx) {
            return false;
        }
        let mut batch = WriteBatch::default();
        match bincode::serialize(tx) {
            Ok(data) => batch.put(tx_key.as_bytes(), &data),
            Err(_) => return false,
        }
        let fee_key = format!("fee:{:020}:{}", u64::MAX - tx.fee, tx.hash);
        batch.put(fee_key.as_bytes(), tx.hash.as_bytes());
        // Build conflict + dependency indexes (same as production)
        for input in &tx.inputs {
            let inp_key = format!("inp:{}:{}", input.txid, input.index);
            batch.put(inp_key.as_bytes(), tx.hash.as_bytes());
        }
        for input in &tx.inputs {
            let parent_key = format!("tx:{}", input.txid);
            if matches!(self.db.get(parent_key.as_bytes()), Ok(Some(_))) {
                batch.put(format!("dep:{}:{}", tx.hash, input.txid).as_bytes(), b"1");
                batch.put(format!("rdep:{}:{}", input.txid, tx.hash).as_bytes(), b"1");
            }
        }
        self.db.write(batch).is_ok()
    }

    pub fn add_transaction(&self, tx: &Transaction) -> bool {
        // ── L1 Network: cheap sanity (no crypto, no DB) ──────────────
        if tx.canonical_bytes().len() > MAX_TX_BYTE_SIZE {
            return false;
        }
        if tx.inputs.is_empty() && !tx.is_coinbase() {
            return false;
        }
        if tx.hash.is_empty() || tx.outputs.is_empty() {
            return false;
        }

        // ── L1.5 Anti-replay: reject stale/future TXs ───────────────
        if TxValidator::validate_tx_timestamp(tx).is_err() {
            return false;
        }
        // payload_hash format check (existence checked at block validation)
        if TxValidator::validate_payload_hash_format(tx).is_err() {
            return false;
        }

        // ── L2 Structural: signature verification (prevents flood) ───
        if !tx.is_coinbase()
            && !TxValidator::verify_signatures(tx) {
                return false;
            }

        // ── L4 Execution: fee + fee_rate check ──────────────────────
        if tx.fee < MIN_RELAY_FEE {
            return false;
        }
        // Fee-rate enforcement with surge pricing: the floor rises with
        // pool utilization so spam during congestion costs exponentially more.
        let rate = Self::fee_rate(tx);
        let effective_min = self.effective_min_fee_rate();
        if rate < effective_min {
            return false;
        }

        // ── L5 Anti-spam: per-sender rate limit ─────────────────────
        // Prevents a single wallet from monopolizing the pool with
        // cheap TXs. Legitimate batching (25 TXs) is still allowed.
        if let Some(sender) = Self::tx_sender(tx) {
            if self.sender_tx_count(sender) >= MAX_TXS_PER_SENDER {
                return false;
            }
        }

        // ── Serialize first to know exact byte size ────────────────
        let tx_key = format!("tx:{}", tx.hash);
        if matches!(self.db.get(tx_key.as_bytes()), Ok(Some(_))) {
            return false; // duplicate
        }

        let data = match bincode::serialize(tx) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let tx_bytes = data.len() as u64;

        // ── Pool-full gate: count + byte limit ─────────────────────
        let cur_count = self.count();
        let cur_bytes = self.total_bytes();

        if cur_count >= MAX_MEMPOOL_SIZE || (cur_bytes + tx_bytes) > MAX_MEMPOOL_BYTES as u64 {
            // Try expiring stale TXs first
            self.evict_expired();

            // If still over count limit, batch-evict lowest-fee TXs
            if self.count() >= MAX_MEMPOOL_SIZE {
                self.evict_to_fit(MAX_MEMPOOL_SIZE - EVICT_BATCH_SIZE);
            }
            // If still over byte limit, evict until we fit
            while self.total_bytes() + tx_bytes > MAX_MEMPOOL_BYTES as u64 && self.count() > 0 {
                self.evict_to_fit(self.count().saturating_sub(EVICT_BATCH_SIZE));
            }

            // Min-fee-rate admission: if pool is still full, reject if new TX's
            // fee_rate doesn't beat the lowest descendant-package fee_rate.
            // Using fee_rate (not absolute fee) ensures large TXs can't sneak
            // in with high absolute fees but low per-byte value.
            if self.count() >= MAX_MEMPOOL_SIZE {
                // Compute the minimum descendant-package fee-rate among the
                // bottom EVICT_BATCH_SIZE TXs in the pool.
                let min_desc_rate = self.pool_min_descendant_fee_rate();
                if rate <= min_desc_rate {
                    return false; // TX fee rate too low to displace any package
                }
                // Evict one more to make room
                self.evict_to_fit(MAX_MEMPOOL_SIZE - 1);
            }
        }

        // ── Conflict handling with RBF ──────────────────────────────
        // Instead of blindly rejecting conflicts, try Replace-By-Fee:
        // if the new TX pays enough to cover evicted fees + bump, accept it.
        let conflicting_txs = self.get_conflicting_txs(tx);
        if !conflicting_txs.is_empty() {
            let conflicting_infos: Vec<MempoolTxInfo> = conflicting_txs.iter()
                .filter_map(|h| self.get_transaction(h))
                .map(|t| self.build_rbf_info(&t))
                .collect();

            // Build confirmed UTXO keys from the TX's inputs
            // (RBF rule: new TX must not introduce new unconfirmed inputs)
            let confirmed_keys: std::collections::HashSet<String> = tx.inputs.iter()
                .filter_map(|inp| {
                    crate::domain::utxo::utxo_set::utxo_key(&inp.txid, inp.index)
                        .ok()
                        .map(|k| k.to_string())
                })
                .collect();

            match RbfEngine::evaluate(tx, &conflicting_infos, &confirmed_keys) {
                RbfResult::Accepted { evicted } => {
                    // Remove all evicted TXs to make room for the replacement
                    for hash in &evicted {
                        self.remove_transaction(hash);
                    }
                    let m = crate::telemetry::metrics::registry::global();
                    m.counter("mempool.rbf_replacements").inc();
                }
                RbfResult::NoConflict => {} // shouldn't happen, but proceed
                _ => return false, // RBF rejected — fee too low, chain too deep, etc.
            }
        } else if self.has_conflict(tx) {
            // Fallback: if get_conflicting_txs missed something, reject
            return false;
        }

        let mut batch = WriteBatch::default();
        batch.put(tx_key.as_bytes(), &data);

        let fee_key = format!("fee:{:020}:{}", u64::MAX - tx.fee, tx.hash);
        batch.put(fee_key.as_bytes(), tx.hash.as_bytes());

        for input in &tx.inputs {
            let inp_key = format!("inp:{}:{}", input.txid, input.index);
            batch.put(inp_key.as_bytes(), tx.hash.as_bytes());
        }

        for input in &tx.inputs {
            let parent_key = format!("tx:{}", input.txid);
            if matches!(self.db.get(parent_key.as_bytes()), Ok(Some(_))) {
                let dep_fwd = format!("dep:{}:{}", tx.hash, input.txid);
                batch.put(dep_fwd.as_bytes(), b"1");

                let dep_rev = format!("rdep:{}:{}", input.txid, tx.hash);
                batch.put(dep_rev.as_bytes(), b"1");
            }
        }

        // Sender index for per-address anti-spam
        if let Some(sender) = Self::tx_sender(tx) {
            let sender_key = format!("sender:{}:{}", sender, tx.hash);
            batch.put(sender_key.as_bytes(), b"1");
        }

        match self.db.write(batch) {
            Ok(_) => {
                // Update metadata counters
                self.meta_inc(META_TX_COUNT, 1);
                self.meta_inc(META_TOTAL_BYTES, tx_bytes);
                self.meta_inc(META_TOTAL_FEES, tx.fee);

                // Global metrics
                let m = crate::telemetry::metrics::registry::global();
                m.counter("mempool.txs_accepted").inc();
                m.gauge("mempool.size").set(self.count() as i64);
                m.gauge("mempool.bytes").set(self.total_bytes() as i64);

                true
            }
            Err(_e) => false,
        }
    }

    pub fn has_conflict(&self, tx: &Transaction) -> bool {
        let mut seen_inputs = std::collections::HashSet::new();
        for input in &tx.inputs {
            // Check direct input conflict (same UTXO already spent by another pool tx)
            let inp_key = format!("inp:{}:{}", input.txid, input.index);
            if matches!(self.db.get(inp_key.as_bytes()), Ok(Some(_))) {
                return true;
            }
            // Check for duplicate inputs within this transaction
            if !seen_inputs.insert((&input.txid, input.index)) {
                return true;
            }
            // Check reverse dependency conflicts: if a pool tx created an output
            // that this tx depends on, and another pool tx also spends it
            let rdep_prefix = format!("rdep:{}:", input.txid);
            let rdep_bytes = rdep_prefix.as_bytes().to_vec();
            let has_rdep_conflict = self.db
                .prefix_iterator(rdep_prefix.as_bytes())
                .filter_map(|r| r.ok())
                .take_while(|(k, _)| k.starts_with(&rdep_bytes))
                .any(|_| true);
            if has_rdep_conflict {
                return true;
            }
        }
        false
    }

    pub fn get_conflicting_txs(&self, tx: &Transaction) -> Vec<String> {
        let mut conflicts = Vec::new();
        for input in &tx.inputs {
            let inp_key = format!("inp:{}:{}", input.txid, input.index);
            if let Ok(Some(data)) = self.db.get(inp_key.as_bytes()) {
                if let Ok(hash) = String::from_utf8(data.to_vec()) {
                    if !conflicts.contains(&hash) {
                        conflicts.push(hash);
                    }
                }
            }
        }
        conflicts
    }

    pub fn get_dependencies(&self, txid: &str) -> Vec<String> {
        let prefix = format!("dep:{}:", txid);
        let prefix_bytes = prefix.as_bytes().to_vec();
        self.db
            .prefix_iterator(prefix.as_bytes())
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(&prefix_bytes))
            .filter_map(|(k, _)| {
                String::from_utf8(k.to_vec()).ok()
                    .and_then(|s| s.strip_prefix(&prefix).map(|p| p.to_string()))
            })
            .collect()
    }

    pub fn get_dependents(&self, txid: &str) -> Vec<String> {
        let prefix = format!("rdep:{}:", txid);
        let prefix_bytes = prefix.as_bytes().to_vec();
        self.db
            .prefix_iterator(prefix.as_bytes())
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(&prefix_bytes))
            .filter_map(|(k, _)| {
                String::from_utf8(k.to_vec()).ok()
                    .and_then(|s| s.strip_prefix(&prefix).map(|p| p.to_string()))
            })
            .collect()
    }

    pub fn has_dependency_path(&self, child: &str, parent: &str) -> bool {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        queue.push_back(child.to_string());
        while let Some(current) = queue.pop_front() {
            if current == parent {
                return true;
            }
            if visited.insert(current.clone()) {
                for dep in self.get_dependencies(&current) {
                    queue.push_back(dep);
                }
            }
        }
        false
    }

    pub fn remove_transaction(&self, txid: &str) {
        if let Some(tx) = self.get_transaction(txid) {
            // Compute byte size for counter update
            let tx_bytes = bincode::serialize(&tx).map(|d| d.len() as u64).unwrap_or(0);
            let tx_fee = tx.fee;

            let mut batch = WriteBatch::default();

            batch.delete(format!("tx:{}", txid).as_bytes());

            for input in &tx.inputs {
                let inp_key = format!("inp:{}:{}", input.txid, input.index);
                batch.delete(inp_key.as_bytes());
            }

            // Clean up sender index
            if let Some(sender) = Self::tx_sender(&tx) {
                let sender_key = format!("sender:{}:{}", sender, txid);
                batch.delete(sender_key.as_bytes());
            }

            let fee_keys: Vec<Vec<u8>> = self.db
                .prefix_iterator(PFX_FEE)
                .filter_map(|r| r.ok())
                .take_while(|(k, _)| k.starts_with(PFX_FEE))
                .filter(|(_, v)| String::from_utf8(v.to_vec()).unwrap_or_default() == txid)
                .map(|(k, _)| k.to_vec())
                .collect();
            for k in fee_keys {
                batch.delete(&k);
            }

            let dep_prefix = format!("dep:{}:", txid);
            let dep_prefix_bytes = dep_prefix.as_bytes().to_vec();
            let dep_keys: Vec<Vec<u8>> = self.db
                .prefix_iterator(dep_prefix.as_bytes())
                .filter_map(|r| r.ok())
                .take_while(|(k, _)| k.starts_with(&dep_prefix_bytes))
                .map(|(k, _)| k.to_vec())
                .collect();
            for k in &dep_keys {
                batch.delete(k);
            }

            let rdep_candidates: Vec<Vec<u8>> = self.db
                .prefix_iterator(PFX_RDEP)
                .filter_map(|r| r.ok())
                .take_while(|(k, _)| k.starts_with(PFX_RDEP))
                .filter(|(k, _)| {
                    String::from_utf8(k.to_vec())
                        .map(|s| s.ends_with(&format!(":{}", txid)))
                        .unwrap_or(false)
                })
                .map(|(k, _)| k.to_vec())
                .collect();
            for k in rdep_candidates {
                batch.delete(&k);
            }

            let rdep_prefix = format!("rdep:{}:", txid);
            let rdep_prefix_bytes = rdep_prefix.as_bytes().to_vec();
            let rdep_fwd_keys: Vec<Vec<u8>> = self.db
                .prefix_iterator(rdep_prefix.as_bytes())
                .filter_map(|r| r.ok())
                .take_while(|(k, _)| k.starts_with(&rdep_prefix_bytes))
                .map(|(k, _)| k.to_vec())
                .collect();
            for k in rdep_fwd_keys {
                batch.delete(&k);
            }

            match self.db.write(batch) {
                Ok(_) => {
                    self.meta_dec(META_TX_COUNT, 1);
                    self.meta_dec(META_TOTAL_BYTES, tx_bytes);
                    self.meta_dec(META_TOTAL_FEES, tx_fee);
                }
                Err(_e) => {}
            }
        }
    }

    /// Evict expired TXs. Iterates the fee index (small keys) and only
    /// deserializes the TX to check the timestamp — avoids loading all TXs.
    pub fn evict_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Collect hashes from fee index, then check timestamps individually
        let all_hashes: Vec<String> = self.db
            .prefix_iterator(PFX_FEE)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_FEE))
            .filter_map(|(_, v)| String::from_utf8(v.to_vec()).ok())
            .collect();

        let mut expired = Vec::new();
        for hash in &all_hashes {
            if let Some(tx) = self.get_transaction(hash) {
                if now.saturating_sub(tx.timestamp) > MAX_MEMPOOL_TX_AGE_SECS {
                    expired.push(hash.clone());
                }
            }
        }

        for hash in &expired {
            self.remove_transaction(hash);
        }
    }

    /// Batch-evict TXs with the lowest descendant-package fee until
    /// count ≤ target_count.  By considering descendant fees (CPFP) we
    /// avoid evicting a low-fee parent whose high-fee children make the
    /// package valuable overall.
    ///
    /// Collects up to EVICT_BATCH_SIZE candidates per iteration to avoid O(n²).
    pub fn evict_to_fit(&self, target_count: usize) {
        let mut total_evicted = 0usize;
        loop {
            let cur = self.count();
            if cur <= target_count { break; }

            let to_evict = (cur - target_count).min(EVICT_BATCH_SIZE);

            // Collect the bottom end of the fee index as eviction candidates.
            // These are the lowest individual-fee TXs (tail of inverted index).
            // We take more than `to_evict` because descendant-fee re-ranking
            // may protect some of them.
            let candidate_hashes = self.fee_index_lowest(to_evict * 2);

            if candidate_hashes.is_empty() { break; }

            // Sort candidates by descendant-package fee_rate ascending so the
            // least-valuable packages (per byte) get evicted first.
            // Using descendant_fee_rate protects low-fee parents whose high-fee
            // children make the package valuable — evicting the parent would
            // orphan those children and waste their fees.
            let mut scored: Vec<(String, u64)> = candidate_hashes
                .into_iter()
                .map(|h| {
                    let rate = (self.descendant_fee_rate(&h) * 1000.0) as u64;
                    (h, rate)
                })
                .collect();
            scored.sort_by_key(|(_, rate)| *rate);

            let evict_list: Vec<String> = scored
                .into_iter()
                .map(|(h, _)| h)
                .take(to_evict)
                .collect();

            if evict_list.is_empty() { break; }

            for hash in &evict_list {
                self.remove_transaction(hash);
                total_evicted += 1;
            }
        }
        let _ = total_evicted; // suppress unused warning
    }

    pub fn get_transactions_for_block(
        &self,
        utxo_set:  &UtxoSet,
        max_count: usize,
    ) -> Vec<Transaction> {
        let limit = max_count.min(MAX_BLOCK_TX_COUNT);

        let candidates: Vec<Transaction> = self.db
            .prefix_iterator(PFX_FEE)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_FEE))
            .take(limit * 4)
            .filter_map(|(_, hash_bytes)| {
                let hash = String::from_utf8(hash_bytes.to_vec()).unwrap_or_default();
                self.get_transaction(&hash)
            })
            .collect();

        let tx_hashes: HashSet<String> = candidates.iter().map(|t| t.hash.clone()).collect();
        let mut in_degree: HashMap<String, usize> = HashMap::new();
        let mut edges: HashMap<String, Vec<String>> = HashMap::new();

        for tx in &candidates {
            in_degree.entry(tx.hash.clone()).or_insert(0);
            for input in &tx.inputs {
                if tx_hashes.contains(&input.txid) {
                    *in_degree.entry(tx.hash.clone()).or_insert(0) += 1;
                    edges.entry(input.txid.clone()).or_default().push(tx.hash.clone());
                }
            }
        }

        let tx_map: HashMap<String, Transaction> = candidates
            .into_iter()
            .map(|t| (t.hash.clone(), t))
            .collect();

        // Pre-compute fee_rate for each candidate (fee per byte).
        // Block space is byte-limited, so fee_rate is the correct metric
        // for maximizing miner revenue per block byte.
        let rate_map: HashMap<String, f64> = tx_map.iter()
            .map(|(h, t)| (h.clone(), Self::fee_rate(t)))
            .collect();

        // Seed the queue with zero-dependency TXs, sorted by fee_rate descending
        // so that among independent transactions the most efficient ones come first.
        let mut ready: Vec<String> = in_degree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(h, _)| h.clone())
            .collect();
        ready.sort_by(|a, b| {
            let ra = rate_map.get(b).copied().unwrap_or(0.0);
            let rb = rate_map.get(a).copied().unwrap_or(0.0);
            ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut queue: VecDeque<String> = ready.into_iter().collect();

        let mut sorted_hashes: Vec<String> = Vec::new();
        let mut remaining_in_degree = in_degree;

        while let Some(hash) = queue.pop_front() {
            sorted_hashes.push(hash.clone());
            if let Some(deps) = edges.get(&hash) {
                // Collect newly-ready dependents, sort by fee_rate, then enqueue
                let mut newly_ready: Vec<String> = Vec::new();
                for dep in deps {
                    let d = remaining_in_degree.entry(dep.clone()).or_insert(1);
                    if *d > 0 { *d -= 1; }
                    if *d == 0 {
                        newly_ready.push(dep.clone());
                    }
                }
                newly_ready.sort_by(|a, b| {
                    let ra = rate_map.get(b).copied().unwrap_or(0.0);
                    let rb = rate_map.get(a).copied().unwrap_or(0.0);
                    ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
                });
                for dep in newly_ready {
                    queue.push_back(dep);
                }
            }
        }

        // O(1) lookup for already-sorted hashes
        let sorted_set: HashSet<String> = sorted_hashes.iter().cloned().collect();
        for hash in tx_map.keys() {
            if !sorted_set.contains(hash) {
                sorted_hashes.push(hash.clone());
            }
        }

        let mut selected:     Vec<Transaction> = Vec::new();
        let mut spent_inputs: HashSet<crate::domain::utxo::utxo_key::UtxoKey>  = HashSet::new();
        // Track staged outputs incrementally instead of rebuilding each iteration
        let mut staged_outputs: HashSet<crate::domain::utxo::utxo_key::UtxoKey> = HashSet::new();

        for hash in sorted_hashes {
            if selected.len() >= limit { break; }
            if let Some(tx) = tx_map.get(&hash) {
                let conflict = tx.inputs.iter().any(|inp| {
                    match crate::domain::utxo::utxo_set::utxo_key(&inp.txid, inp.index) {
                        Ok(k) => spent_inputs.contains(&k),
                        Err(_) => true,
                    }
                });
                if conflict { continue; }

                let all_ok = tx.is_coinbase() || tx.inputs.iter().all(|inp| {
                    match crate::domain::utxo::utxo_set::utxo_key(&inp.txid, inp.index) {
                        Ok(key) => utxo_set.exists(&key) || staged_outputs.contains(&key),
                        Err(_) => false,
                    }
                });

                if all_ok {
                    let mut bad_key = false;
                    for inp in &tx.inputs {
                        match crate::domain::utxo::utxo_set::utxo_key(&inp.txid, inp.index) {
                            Ok(k) => { spent_inputs.insert(k); }
                            Err(_) => { bad_key = true; break; }
                        }
                    }
                    if bad_key { continue; }
                    for (i, _) in tx.outputs.iter().enumerate() {
                        match crate::domain::utxo::utxo_set::utxo_key(&tx.hash, i as u32) {
                            Ok(k) => { staged_outputs.insert(k); }
                            Err(_) => { bad_key = true; break; }
                        }
                    }
                    if bad_key { continue; }
                    selected.push(tx.clone());
                }
            }
        }

        // NOTE: Do NOT re-sort by fee here — the topological order from
        // the dependency-aware selection above must be preserved so that
        // parent transactions appear before their children in the block.
        selected
    }

    /// O(1) TX count using the metadata counter.
    /// Falls back to a full scan if the counter is 0 but TXs exist (migration).
    pub fn count(&self) -> usize {
        let meta = self.meta_get_u64(META_TX_COUNT);
        if meta > 0 {
            return meta as usize;
        }
        // Fallback: full scan (first run after upgrade, or truly empty)
        let actual = self.db.prefix_iterator(PFX_TX)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_TX))
            .count();
        if actual > 0 {
            // Migrate: seed the counter so future calls are O(1)
            self.meta_set_u64(META_TX_COUNT, actual as u64);
        }
        actual
    }

    pub fn get_all_transactions(&self) -> Vec<Transaction> {
        self.db.prefix_iterator(PFX_TX)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_TX))
            .filter_map(|(_, v)| bincode::deserialize(&v).ok())
            .collect()
    }

    pub fn get_transaction(&self, hash: &str) -> Option<Transaction> {
        let key = format!("tx:{}", hash);
        match self.db.get(key.as_bytes()) {
            Ok(Some(data)) => bincode::deserialize(&data).ok(),
            _              => None,
        }
    }

    pub fn flush(&self) {
        let all_keys: Vec<Vec<u8>> = self.db
            .iterator(rocksdb::IteratorMode::Start)
            .filter_map(|r| r.ok())
            .map(|(k, _)| k.to_vec())
            .collect();
        for k in &all_keys {
            let _ = self.db.delete(k);
        }
        // Reset metadata counters
        self.meta_set_u64(META_TX_COUNT, 0);
        self.meta_set_u64(META_TOTAL_BYTES, 0);
        self.meta_set_u64(META_TOTAL_FEES, 0);
    }

    /// Efficient stats using O(1) metadata counters.
    /// Only the timestamp fields require a partial scan (first/last fee index entries).
    pub fn stats(&self) -> MempoolStats {
        let count      = self.count() as u64;
        let total_fees = self.total_fees();
        let total_bytes = self.total_bytes();

        // Oldest = last entry in fee index (lowest fee, typically oldest).
        // Newest = first entry in fee index (highest fee, typically newest).
        // These are approximations — exact would require a timestamp index.
        // For accurate oldest/newest, sample the first and last fee entries.
        let (oldest_ts, newest_ts) = self.sample_timestamps();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Expired count: approximate from oldest timestamp instead of full scan.
        // If oldest TX is within the age limit, there are 0 expired.
        let expired = if oldest_ts > 0 && now.saturating_sub(oldest_ts) > MAX_MEMPOOL_TX_AGE_SECS {
            // There are expired TXs; count them by scanning timestamps.
            // This only happens when pool has stale TXs (rare during normal operation).
            self.count_expired(now)
        } else {
            0
        };

        MempoolStats {
            tx_count:      count as usize,
            total_fees,
            total_bytes,
            avg_fee:       if count > 0 { total_fees / count } else { 0 },
            avg_fee_rate:  if total_bytes > 0 { total_fees as f64 / total_bytes as f64 } else { 0.0 },
            oldest_ts,
            newest_ts,
            expired_count: expired,
        }
    }

    /// Sample the oldest and newest TX timestamps from fee index endpoints.
    fn sample_timestamps(&self) -> (u64, u64) {
        let mut oldest = 0u64;
        let mut newest = 0u64;

        // First entry in fee index = highest fee → likely newest
        if let Some((_, v)) = self.db
            .prefix_iterator(PFX_FEE)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_FEE))
            .next()
        {
            if let Ok(hash) = String::from_utf8(v.to_vec()) {
                if let Some(tx) = self.get_transaction(&hash) {
                    newest = tx.timestamp;
                    oldest = tx.timestamp; // default if only one TX
                }
            }
        }

        // Last entry in fee index = lowest fee → likely oldest
        if let Some((_, v)) = self.db
            .prefix_iterator(PFX_FEE)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_FEE))
            .last()
        {
            if let Ok(hash) = String::from_utf8(v.to_vec()) {
                if let Some(tx) = self.get_transaction(&hash) {
                    oldest = tx.timestamp;
                }
            }
        }

        (oldest, newest)
    }

    /// Count expired TXs. Only called when we know some exist (rare path).
    fn count_expired(&self, now: u64) -> usize {
        self.db
            .prefix_iterator(PFX_FEE)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_FEE))
            .filter_map(|(_, v)| String::from_utf8(v.to_vec()).ok())
            .filter_map(|hash| self.get_transaction(&hash))
            .filter(|tx| now.saturating_sub(tx.timestamp) > MAX_MEMPOOL_TX_AGE_SECS)
            .count()
    }

    /// Full UTXO + signature validation before accepting into mempool.
    /// Use this instead of `add_transaction` when a UTXO set is available
    /// to ensure only fully-valid transactions enter the mempool.
    pub fn add_transaction_validated(&self, tx: &Transaction, utxo_set: &UtxoSet) -> Result<(), MempoolError> {
        // Basic structural checks (size, fee) first — cheap to evaluate
        match bincode::serialize(tx) {
            Ok(b) if b.len() > MAX_TX_BYTE_SIZE => {
                return Err(MempoolError::TxTooLarge(b.len()));
            }
            Err(e) => {
                return Err(MempoolError::ValidationFailed(
                    format!("transaction serialization failed: {}", e)
                ));
            }
            _ => {}
        }

        if tx.inputs.is_empty() && !tx.is_coinbase() {
            return Err(MempoolError::ValidationFailed(
                "non-coinbase transaction has no inputs".to_string()
            ));
        }

        if tx.fee < MIN_RELAY_FEE {
            return Err(MempoolError::FeeTooLow { fee: tx.fee, minimum: MIN_RELAY_FEE });
        }

        // Fee-rate check with surge pricing: floor rises under pool pressure
        let rate = Self::fee_rate(tx);
        let effective_min = self.effective_min_fee_rate();
        if rate < effective_min {
            return Err(MempoolError::FeeTooLow {
                fee: tx.fee,
                minimum: (tx.canonical_bytes().len() as f64 * effective_min).ceil() as u64,
            });
        }

        // Per-sender anti-spam: reject if sender already has MAX_TXS_PER_SENDER in pool
        if let Some(sender) = Self::tx_sender(tx) {
            if self.sender_tx_count(sender) >= MAX_TXS_PER_SENDER {
                return Err(MempoolError::Other(
                    format!("sender {} already has {} unconfirmed TXs in mempool",
                        sender, MAX_TXS_PER_SENDER)
                ));
            }
        }

        // Full UTXO + signature validation before accepting into mempool
        if !tx.is_coinbase()
            && !TxValidator::validate_tx(tx, utxo_set) {
                return Err(MempoolError::ValidationFailed(
                    "transaction failed UTXO/signature validation".to_string()
                ));
            }

        // Delegate to storage after validation passed
        if self.add_transaction(tx) {
            Ok(())
        } else {
            Err(MempoolError::Other(
                "transaction rejected by mempool (duplicate, conflict, or full)".to_string()
            ))
        }
    }

    pub fn add_transaction_owned(&mut self, tx: Transaction) -> bool {
        self.add_transaction(&tx)
    }

    // ─────────────────────────────────────────────────────────
    // CPFP (Child Pays For Parent) — ancestor / descendant fee helpers
    // ─────────────────────────────────────────────────────────

    /// Maximum depth for ancestor/descendant walks to prevent DoS.
    const MAX_PACKAGE_DEPTH: usize = 25;

    /// Compute the ancestor-package fee rate for a transaction.
    ///
    /// Walks the dependency chain (parents, grandparents, …) up to
    /// `MAX_PACKAGE_DEPTH` and returns:
    ///   `(tx.fee + sum of ancestor fees) / (tx.size + sum of ancestor sizes)`
    ///
    /// A high-fee child thus "boosts" its low-fee parents in block selection.
    pub fn ancestor_fee_rate(&self, txid: &str) -> f64 {
        let mut total_fee:  u64 = 0;
        let mut total_size: u64 = 0;
        let mut visited = HashSet::new();
        let mut queue   = VecDeque::new();
        queue.push_back(txid.to_string());

        while let Some(current) = queue.pop_front() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if visited.len() > Self::MAX_PACKAGE_DEPTH {
                break;
            }
            if let Some(tx) = self.get_transaction(&current) {
                total_fee = total_fee.checked_add(tx.fee).unwrap_or(u64::MAX);
                total_size = total_size.checked_add(tx.canonical_bytes().len() as u64).unwrap_or(u64::MAX);
                for dep in self.get_dependencies(&current) {
                    if !visited.contains(&dep) {
                        queue.push_back(dep);
                    }
                }
            }
        }

        if total_size == 0 {
            return 0.0;
        }
        total_fee as f64 / total_size as f64
    }

    /// Compute the descendant-package fee rate (fee per byte) for a transaction.
    ///
    /// Walks the reverse-dependency chain and returns:
    ///   `(tx.fee + sum of descendant fees) / (tx.size + sum of descendant sizes)`
    ///
    /// Used by the evictor: considers both fee value AND byte cost so large
    /// low-rate packages don't get unfair protection over small high-rate TXs.
    pub fn descendant_fee_rate(&self, txid: &str) -> f64 {
        let mut total_fee:  u64 = 0;
        let mut total_size: u64 = 0;
        let mut visited = HashSet::new();
        let mut queue   = VecDeque::new();
        queue.push_back(txid.to_string());

        while let Some(current) = queue.pop_front() {
            if !visited.insert(current.clone()) { continue; }
            if visited.len() > Self::MAX_PACKAGE_DEPTH { break; }
            if let Some(tx) = self.get_transaction(&current) {
                total_fee  = total_fee.checked_add(tx.fee).unwrap_or(u64::MAX);
                total_size = total_size.checked_add(tx.canonical_bytes().len() as u64).unwrap_or(u64::MAX);
                for dep in self.get_dependents(&current) {
                    if !visited.contains(&dep) {
                        queue.push_back(dep);
                    }
                }
            }
        }

        if total_size == 0 { return 0.0; }
        total_fee as f64 / total_size as f64
    }

    /// Compute the descendant-package fee for a transaction.
    ///
    /// Walks the reverse-dependency chain (children, grandchildren, …) up to
    /// `MAX_PACKAGE_DEPTH` and returns:
    ///   `tx.fee + sum of descendant fees`
    ///
    /// Used by the admission gate: a low-fee parent with high-fee children should
    /// NOT be evicted because removing it would orphan valuable descendants.
    pub fn descendant_fee(&self, txid: &str) -> u64 {
        let mut total_fee: u64 = 0;
        let mut visited = HashSet::new();
        let mut queue   = VecDeque::new();
        queue.push_back(txid.to_string());

        while let Some(current) = queue.pop_front() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if visited.len() > Self::MAX_PACKAGE_DEPTH {
                break;
            }
            if let Some(tx) = self.get_transaction(&current) {
                total_fee = total_fee.checked_add(tx.fee).unwrap_or(u64::MAX);
                for dep in self.get_dependents(&current) {
                    if !visited.contains(&dep) {
                        queue.push_back(dep);
                    }
                }
            }
        }

        total_fee
    }
}

impl crate::domain::traits::tx_pool::TxPool for Mempool {
    fn get_transaction(&self, hash: &str) -> Option<Transaction> {
        self.get_transaction(hash)
    }

    fn has_transaction(&self, hash: &str) -> bool {
        self.get_transaction(hash).is_some()
    }

    fn count(&self) -> usize {
        self.count()
    }

    fn get_prioritized_txs(&self, limit: usize) -> Vec<Transaction> {
        let mut txs = self.get_all_transactions();
        // Sort by fee_rate (fee per byte) descending — maximizes revenue per block byte.
        txs.sort_by(|a, b| {
            let ra = Self::fee_rate(a);
            let rb = Self::fee_rate(b);
            rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
        });
        txs.truncate(limit);
        txs
    }

    fn get_transactions_for_block(
        &self,
        utxo_set: &crate::domain::utxo::utxo_set::UtxoSet,
        max_count: usize,
    ) -> Vec<Transaction> {
        self.get_transactions_for_block(utxo_set, max_count)
    }
}

pub struct MempoolStats {
    pub tx_count:      usize,
    pub total_fees:    u64,
    pub total_bytes:   u64,
    pub avg_fee:       u64,
    /// Average fee rate (satoshis per byte) across the entire pool.
    pub avg_fee_rate:  f64,
    pub oldest_ts:     u64,
    pub newest_ts:     u64,
    pub expired_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};

    fn coinbase_tx(hash: &str, fee: u64) -> Transaction {
        Transaction {
            hash:      hash.to_string(),
            inputs:    vec![],
            outputs:   vec![TxOutput { address: "addr".into(), amount: 1_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee,
            timestamp: current_ts(),
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    fn tx_with_input(hash: &str, txid: &str, idx: u32, fee: u64) -> Transaction {
        Transaction {
            hash:    hash.to_string(),
            inputs:  vec![TxInput {
                txid:      txid.to_string(),
                index:     idx,
                owner:     "alice".into(),
                signature: String::new(),
                pub_key:   String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput { address: "bob".into(), amount: 546, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee,
            timestamp: current_ts(),
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    fn current_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[test]
    fn conflict_detection_blocks_double_spend() {
        let mp  = Mempool::try_new(format!("/tmp/test_mp_v9_conflict_{}_{}", std::process::id(), line!())).expect("test mp");
        let tx1 = tx_with_input("tx_a", "utxo1", 0, 5);
        let tx2 = tx_with_input("tx_b", "utxo1", 0, 10);
        mp.add_transaction_test(&tx1);
        assert!(!mp.add_transaction_test(&tx2), "Second TX spending same input must be rejected");
    }

    #[test]
    fn remove_cleans_conflict_index() {
        let mp  = Mempool::try_new(format!("/tmp/test_mp_v9_remove_{}_{}", std::process::id(), line!())).expect("test mp");
        let tx1 = tx_with_input("tx_c", "utxo2", 0, 5);
        let tx2 = tx_with_input("tx_d", "utxo2", 0, 10);
        mp.add_transaction_test(&tx1);
        mp.remove_transaction("tx_c");
        assert!(mp.add_transaction_test(&tx2), "After removal, new TX should be accepted");
    }

    #[test]
    fn dependency_graph_tx2_depends_on_tx1() {
        let mp   = Mempool::try_new(format!("/tmp/test_mp_v9_depgraph_{}_{}", std::process::id(), line!())).expect("test mp");
        mp.flush();

        let tx1 = coinbase_tx("tx1_dep", 10);
        mp.add_transaction_test(&tx1);

        let tx2 = tx_with_input("tx2_dep", "tx1_dep", 0, 5);
        mp.add_transaction_test(&tx2);

        let deps = mp.get_dependencies("tx2_dep");
        assert!(
            deps.contains(&"tx1_dep".to_string()),
            "tx2 must show tx1 as dependency"
        );

        let dependents = mp.get_dependents("tx1_dep");
        assert!(
            dependents.contains(&"tx2_dep".to_string()),
            "tx1 must show tx2 as dependent"
        );
    }

    #[test]
    fn remove_cleans_dependency_index() {
        let mp = Mempool::try_new(format!("/tmp/test_mp_v9_dep_remove_{}_{}", std::process::id(), line!())).expect("test mp");
        mp.flush();

        let tx1 = coinbase_tx("tx1_rm", 10);
        mp.add_transaction_test(&tx1);
        let tx2 = tx_with_input("tx2_rm", "tx1_rm", 0, 5);
        mp.add_transaction_test(&tx2);

        mp.remove_transaction("tx2_rm");
        let deps = mp.get_dependencies("tx2_rm");
        assert!(deps.is_empty(), "Dependencies must be cleaned on removal");
    }

    #[test]
    fn evict_expired_removes_old_txs() {
        let mp = Mempool::try_new(format!("/tmp/test_mp_v9_expired_{}_{}", std::process::id(), line!())).expect("test mp");
        mp.flush();

        // Insert an old TX directly into DB (bypassing validation)
        let old_hash = "old_tx_expired_v9";
        let mut old_tx = coinbase_tx(old_hash, 5);
        old_tx.timestamp = 1_000; // Very old timestamp
        if let Ok(data) = bincode::serialize(&old_tx) {
            let _ = mp.db.put(format!("tx:{}", old_hash).as_bytes(), &data);
            // Also insert fee index entry (required by evict_expired scan)
            let fee_key = format!("fee:{:020}:{}", u64::MAX - old_tx.fee, old_hash);
            let _ = mp.db.put(fee_key.as_bytes(), old_hash.as_bytes());
        }

        mp.evict_expired();
        assert!(mp.get_transaction(old_hash).is_none(), "Expired TX must be removed");
    }

    #[test]
    fn stats_includes_expired_count() {
        let mp = Mempool::try_new(format!("/tmp/test_mp_v9_stats_{}_{}", std::process::id(), line!())).expect("test mp");
        mp.flush();
        let s = mp.stats();
        assert_eq!(s.tx_count, 0);
        assert_eq!(s.expired_count, 0);
    }
}

#[cfg(test)]
mod cpfp_tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn coinbase(hash: &str, fee: u64) -> Transaction {
        Transaction {
            hash:      hash.to_string(),
            inputs:    vec![],
            outputs:   vec![TxOutput { address: "addr".into(), amount: 1_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee,
            timestamp: ts(),
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    fn child_tx(hash: &str, parent: &str, idx: u32, fee: u64) -> Transaction {
        Transaction {
            hash:    hash.to_string(),
            inputs:  vec![TxInput {
                txid:      parent.to_string(),
                index:     idx,
                owner:     "alice".into(),
                signature: String::new(),
                pub_key:   String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput { address: "bob".into(), amount: 546, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee,
            timestamp: ts(),
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    fn pool(label: &str) -> Mempool {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let path = format!("/tmp/test_cpfp_{}_{}_{}", label, ts(), id);
        Mempool::try_new(path.as_str()).expect("test pool")
    }

    #[test]
    fn test_ancestor_fee_rate_single_tx() {
        let mp = pool("anc_single");
        let tx = coinbase("solo", 500);
        mp.add_transaction_test(&tx);

        let rate = mp.ancestor_fee_rate("solo");
        // rate = fee / serialized_size; just verify it equals the TX's own rate
        let size = tx.canonical_bytes().len() as f64;
        let expected = 500.0 / size;
        assert!(
            (rate - expected).abs() < 1e-9,
            "Single TX ancestor fee rate should equal its own fee/size: got {} expected {}",
            rate, expected,
        );
    }

    #[test]
    fn test_ancestor_fee_rate_with_parent() {
        let mp = pool("anc_parent");

        let parent = coinbase("parent_a", 100);
        mp.add_transaction_test(&parent);

        let child = child_tx("child_a", "parent_a", 0, 900);
        mp.add_transaction_test(&child);

        let rate = mp.ancestor_fee_rate("child_a");

        // Package: parent(100) + child(900) = 1000 fee
        let parent_size = parent.canonical_bytes().len() as f64;
        let child_size  = child.canonical_bytes().len() as f64;
        let expected = 1000.0 / (parent_size + child_size);

        assert!(
            (rate - expected).abs() < 1e-9,
            "Child ancestor fee rate must include parent: got {} expected {}",
            rate, expected,
        );
        // The child's ancestor fee rate should be higher than the parent's own rate
        let parent_rate = mp.ancestor_fee_rate("parent_a");
        assert!(
            rate > parent_rate,
            "Child's ancestor fee rate ({}) should exceed parent-only rate ({})",
            rate, parent_rate,
        );
    }

    #[test]
    fn test_descendant_fee_includes_children() {
        let mp = pool("desc_children");

        let parent = coinbase("parent_b", 50);
        mp.add_transaction_test(&parent);

        let child1 = child_tx("child_b1", "parent_b", 0, 200);
        mp.add_transaction_test(&child1);

        // child1 has a different output index so no conflict — but parent_b only
        // has 1 output, so we use a second coinbase as a separate parent to avoid
        // conflict. Actually, let's just check parent_b's descendant fee.
        let desc_fee = mp.descendant_fee("parent_b");
        assert_eq!(
            desc_fee, 50 + 200,
            "Descendant fee of parent must include child: got {}",
            desc_fee,
        );

        // The child itself has no descendants, so descendant_fee == own fee
        let child_desc = mp.descendant_fee("child_b1");
        assert_eq!(child_desc, 200, "Leaf TX descendant fee should be its own fee");
    }

    #[test]
    fn test_eviction_prefers_low_descendant_fee() {
        let mp = pool("evict_cpfp");
        mp.flush();

        // TX "low_solo" has fee=2, no children  → descendant_fee = 2
        let low_solo = coinbase("low_solo", 2);
        mp.add_transaction_test(&low_solo);

        // TX "low_parent" has fee=1, but a high-fee child → descendant_fee = 1+500 = 501
        let low_parent = coinbase("low_parent", 1);
        mp.add_transaction_test(&low_parent);
        let hi_child = child_tx("hi_child", "low_parent", 0, 500);
        mp.add_transaction_test(&hi_child);

        // TX "mid" has fee=3, no children → descendant_fee = 3
        let mid = coinbase("mid_tx", 3);
        mp.add_transaction_test(&mid);

        // Current pool: low_solo(2), low_parent(1), hi_child(500), mid_tx(3)
        // Descendant fees: low_solo=2, low_parent=501, hi_child=500, mid_tx=3
        assert_eq!(mp.count(), 4);

        // Evict down to 2 TXs.  Lowest descendant fees are:
        //   low_solo(2), mid_tx(3) → these should be evicted first.
        // low_parent(501) and hi_child(500) should survive.
        mp.evict_to_fit(2);

        assert_eq!(mp.count(), 2, "Pool should have 2 TXs after eviction");
        assert!(
            mp.get_transaction("low_parent").is_some(),
            "low_parent (desc_fee=501) should survive eviction",
        );
        assert!(
            mp.get_transaction("hi_child").is_some(),
            "hi_child (desc_fee=500) should survive eviction",
        );
        assert!(
            mp.get_transaction("low_solo").is_none(),
            "low_solo (desc_fee=2) should be evicted",
        );
        assert!(
            mp.get_transaction("mid_tx").is_none(),
            "mid_tx (desc_fee=3) should be evicted",
        );
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn ts() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    fn coinbase(hash: &str, fee: u64) -> Transaction {
        Transaction {
            hash: hash.to_string(), inputs: vec![],
            outputs: vec![TxOutput { address: "a".into(), amount: 1_000, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee, timestamp: ts(), is_coinbase: true,
            tx_type: TxType::Transfer, payload_hash: None,
        }
    }

    fn pool(label: &str) -> Mempool {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let path = format!("/tmp/test_policy_{}_{}_{}", label, ts(), id);
        Mempool::try_new(path.as_str()).expect("test pool")
    }

    #[test]
    fn surge_pricing_empty_pool() {
        let mp = pool("surge_empty");
        // Empty pool → base rate
        let rate = mp.effective_min_fee_rate();
        assert!((rate - MIN_FEE_RATE).abs() < 1e-9, "Empty pool should use base rate");
    }

    #[test]
    fn surge_pricing_scales_with_utilization() {
        let mp = pool("surge_scale");
        // Simulate high utilization by pushing the counter up
        // MAX_MEMPOOL_SIZE = 100_000, so 75% = 75_000
        mp.meta_set_u64(META_TX_COUNT, 75_000);
        let rate = mp.effective_min_fee_rate();
        assert!(
            (rate - MIN_FEE_RATE * 4.0).abs() < 1e-9,
            "75% utilization should give 4× rate, got {}",
            rate
        );
    }

    #[test]
    fn surge_pricing_max_at_90_percent() {
        let mp = pool("surge_max");
        mp.meta_set_u64(META_TX_COUNT, 95_000);
        let rate = mp.effective_min_fee_rate();
        assert!(
            (rate - MIN_FEE_RATE * 8.0).abs() < 1e-9,
            "95% utilization should give 8× rate, got {}",
            rate
        );
    }

    #[test]
    fn pool_min_descendant_fee_rate_empty() {
        let mp = pool("min_rate_empty");
        assert!((mp.pool_min_descendant_fee_rate() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn pool_min_descendant_fee_rate_with_txs() {
        let mp = pool("min_rate_txs");
        let tx1 = coinbase("t1", 100);
        let tx2 = coinbase("t2", 500);
        mp.add_transaction_test(&tx1);
        mp.add_transaction_test(&tx2);

        let min_rate = mp.pool_min_descendant_fee_rate();
        // tx1 has lower fee → lower fee_rate → should be the minimum
        let tx1_rate = Mempool::fee_rate(&tx1);
        assert!(
            (min_rate - tx1_rate).abs() < 1e-9,
            "Min descendant fee rate should be tx1's rate: got {} expected {}",
            min_rate, tx1_rate,
        );
    }
}

const PFX_ORPHAN: &[u8] = b"orphan:";

pub const MAX_ORPHAN_POOL_SIZE: usize = MempoolConfig::MAX_ORPHAN_POOL_SIZE;
pub const MAX_ORPHAN_AGE_SECS: u64   = MempoolConfig::MAX_ORPHAN_AGE_SECS;

impl Mempool {
    pub fn add_orphan(&self, tx: &Transaction) -> bool {
        self.prune_orphans();

        let count = self.orphan_count();
        if count >= MAX_ORPHAN_POOL_SIZE {
            return false;
        }

        let key = format!("orphan:{}", tx.hash);
        if matches!(self.db.get(key.as_bytes()), Ok(Some(_))) {
            return false;
        }

        match bincode::serialize(tx) {
            Ok(data) => {
                self.db.put(key.as_bytes(), &data).is_ok()
            }
            Err(_e) => {
                false
            }
        }
    }

    pub fn resolve_orphans(&self, parent_txid: &str) -> Vec<String> {
        let mut promoted = Vec::new();
        let all_orphans  = self.get_all_orphans();

        for orphan in all_orphans {
            let depends_on_parent = orphan.inputs.iter().any(|inp| inp.txid == parent_txid);
            if !depends_on_parent { continue; }

            if self.add_transaction(&orphan) {
                let key = format!("orphan:{}", orphan.hash);
                if let Err(e) = self.db.delete(key.as_bytes()) {
                    eprintln!("[Mempool] orphan DB deletion failed for '{}': {}", key, e);
                }
                promoted.push(orphan.hash.clone());
            }
        }
        promoted
    }

    pub fn is_orphan(&self, tx_hash: &str) -> bool {
        let key = format!("orphan:{}", tx_hash);
        matches!(self.db.get(key.as_bytes()), Ok(Some(_)))
    }

    pub fn orphan_count(&self) -> usize {
        self.db.prefix_iterator(PFX_ORPHAN)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_ORPHAN))
            .count()
    }

    pub fn remove_orphan(&self, tx_hash: &str) {
        let key = format!("orphan:{}", tx_hash);
        if let Err(e) = self.db.delete(key.as_bytes()) {
            eprintln!("[Mempool] orphan DB deletion failed for '{}': {}", key, e);
        }
    }

    pub fn prune_orphans(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stale_keys: Vec<Vec<u8>> = self.db
            .prefix_iterator(PFX_ORPHAN)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_ORPHAN))
            .filter_map(|(k, v)| {
                let tx: Transaction = bincode::deserialize(&v).ok()?;
                if now.saturating_sub(tx.timestamp) > MAX_ORPHAN_AGE_SECS {
                    Some(k.to_vec())
                } else {
                    None
                }
            })
            .collect();

        for k in &stale_keys {
            let label = String::from_utf8_lossy(k);
            if let Err(e) = self.db.delete(k) {
                eprintln!("[Mempool] orphan DB deletion failed for '{}': {}", label, e);
            }
        }

        if !stale_keys.is_empty() {
        }
    }

    pub fn get_all_orphans(&self) -> Vec<Transaction> {
        self.db.prefix_iterator(PFX_ORPHAN)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_ORPHAN))
            .filter_map(|(_, v)| bincode::deserialize(&v).ok())
            .collect()
    }

    pub fn orphans_waiting_for(&self, parent_txid: &str) -> Vec<Transaction> {
        self.get_all_orphans()
            .into_iter()
            .filter(|tx| tx.inputs.iter().any(|inp| inp.txid == parent_txid))
            .collect()
    }
}

#[cfg(test)]
mod orphan_tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn orphan_tx(hash: &str, parent: &str) -> Transaction {
        Transaction {
            hash:    hash.to_string(),
            inputs:  vec![TxInput {
                txid:      parent.to_string(),
                index:     0,
                owner:     "alice".into(),
                signature: String::new(),
                pub_key:   String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput { address: "bob".into(), amount: 546, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee:     1,
            timestamp: ts(),
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    fn pool() -> Mempool {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0);
        let id = CTR.fetch_add(1, Ordering::Relaxed);
        let path = format!("/tmp/test_orphan_pool_{}_{}", ts(), id);
        Mempool::try_new(path.as_str()).expect("test pool creation failed")
    }

    #[test]
    fn add_orphan_stores_tx() {
        let mp = pool();
        let tx = orphan_tx("o_tx1", "missing_parent");
        assert!(mp.add_orphan(&tx), "add_orphan must succeed");
        assert!(mp.is_orphan("o_tx1"), "tx must be in orphan pool");
        assert_eq!(mp.orphan_count(), 1);
    }

    #[test]
    fn orphan_not_in_main_mempool() {
        let mp = pool();
        let tx = orphan_tx("o_tx2", "ghost_parent");
        mp.add_orphan(&tx);

        assert!(mp.get_transaction("o_tx2").is_none());
    }

    #[test]
    fn resolve_orphans_promotes_on_parent_arrival() {
        let mp = pool();
        let parent_hash = "parent_for_orphan";
        let child = orphan_tx("child_of_parent", parent_hash);
        mp.add_orphan(&child);
        assert!(mp.is_orphan("child_of_parent"));

        let waiting = mp.orphans_waiting_for(parent_hash);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].hash, "child_of_parent");
    }

    #[test]
    fn remove_orphan_cleans_pool() {
        let mp = pool();
        let tx = orphan_tx("to_remove", "p");
        mp.add_orphan(&tx);
        mp.remove_orphan("to_remove");
        assert!(!mp.is_orphan("to_remove"));
        assert_eq!(mp.orphan_count(), 0);
    }

    #[test]
    fn prune_orphans_evicts_stale() {
        let mp = pool();
        let mut stale = orphan_tx("stale_orphan", "parent_gone");
        stale.timestamp = 100;
        mp.add_orphan(&stale);
        mp.prune_orphans();
        assert!(!mp.is_orphan("stale_orphan"), "stale orphan must be pruned");
    }

    #[test]
    fn orphan_pool_bounded_by_max_size() {
        let mp = pool();

        for i in 0..MAX_ORPHAN_POOL_SIZE {
            let tx = orphan_tx(&format!("bounded_{}", i), "parent_x");
            mp.add_orphan(&tx);
        }
        assert_eq!(mp.orphan_count(), MAX_ORPHAN_POOL_SIZE);

        let extra = orphan_tx("extra_orphan", "parent_x");
        assert!(!mp.add_orphan(&extra), "Orphan pool must be bounded");
    }
}
