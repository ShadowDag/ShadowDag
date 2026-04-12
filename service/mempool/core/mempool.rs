// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteBatch};
use std::collections::{HashSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::MempoolError;
use crate::domain::transaction::transaction::{Transaction, TxType};
use crate::domain::transaction::tx_validator::TxValidator;
use crate::domain::utxo::utxo_set::UtxoSet;
use crate::infrastructure::storage::rocksdb::core::db::{open_shared_db, SharedDbSource};
use crate::service::mempool::core::rbf::{RbfEngine, RbfResult, MempoolTxInfo};
use crate::config::node::node_config::NetworkMode;
use crate::{slog_error, slog_warn};

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
const PFX_RDEP:   &[u8] = b"rdep:";
/// Metadata key for tracking total serialized bytes in the pool.
const META_TOTAL_BYTES: &[u8] = b"_meta:total_bytes";
/// Metadata key for tracking TX count without full scan.
const META_TX_COUNT:    &[u8] = b"_meta:tx_count";
/// Metadata key for tracking total fees (for O(1) stats).
const META_TOTAL_FEES:  &[u8] = b"_meta:total_fees";

pub struct Mempool {
    db: Arc<DB>,
    network: NetworkMode,
}

// ─────────────────────────────────────────────────────────
// Internal metadata helpers (atomic counters via RocksDB)
// ─────────────────────────────────────────────────────────
impl Mempool {
    /// Iterate the fee index backward (lowest fee_rate first) and return up to
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
            Ok(_) => 0,
            Err(e) => {
                let key_str = String::from_utf8_lossy(key);
                slog_error!("mempool", "meta_get_u64_read_failed",
                    key => &key_str.to_string(), error => &e.to_string());
                0
            }
        }
    }

    #[inline]
    fn meta_set_u64(&self, key: &[u8], val: u64) {
        if let Err(e) = self.db.put(key, val.to_le_bytes()) {
            let key_str = String::from_utf8_lossy(key);
            slog_error!("mempool", "meta_set_u64_write_failed",
                key => &key_str.to_string(), error => &e.to_string());
        }
    }

    /// Increment a metadata counter by `delta`.
    ///
    /// SAFETY: This is a read-then-write without RocksDB-level atomicity.
    /// However, all Mempool mutations are serialized by the `Arc<Mutex<MempoolManager>>`
    /// in `daemon::mod`, so concurrent access cannot occur in practice.
    /// If Mempool is ever used outside that Mutex, these must be converted to
    /// RocksDB merge operations or wrapped in a WriteBatch.
    #[inline]
    fn meta_inc(&self, key: &[u8], delta: u64) {
        let cur = self.meta_get_u64(key);
        self.meta_set_u64(key, cur.saturating_add(delta));
    }

    /// Decrement a metadata counter by `delta` (saturating).
    ///
    /// SAFETY: Same serialization guarantee as `meta_inc` — see its doc comment.
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
    /// Extract ALL unique sender addresses from a transaction's inputs.
    /// Prevents per-sender limit bypass when a TX has inputs from multiple owners.
    fn tx_senders(tx: &Transaction) -> Vec<&str> {
        if tx.is_coinbase() { return Vec::new(); }
        let mut senders: Vec<&str> = tx.inputs.iter()
            .map(|inp| inp.owner.as_str())
            .collect();
        senders.sort_unstable();
        senders.dedup();
        senders
    }

    // ── Surge pricing ────────────────────────────────────────────────────
    /// Dynamic fee-rate floor that rises **exponentially** with pool utilization.
    ///
    /// Uses a smooth curve: `multiplier = 2^(utilization × 6)`, which gives:
    ///
    /// | Utilization | Multiplier | Effective Min Fee Rate |
    /// |-------------|------------|------------------------|
    /// |    0%       |   1.0×     | 1.0 sat/byte           |
    /// |   25%       |   2.8×     | 2.8 sat/byte           |
    /// |   50%       |   8.0×     | 8.0 sat/byte           |
    /// |   75%       |  22.6×     | 22.6 sat/byte          |
    /// |   90%       |  39.4×     | 39.4 sat/byte          |
    /// |  100%       |  64.0×     | 64.0 sat/byte (cap)    |
    ///
    /// Smooth curve prevents fee-gaming at step boundaries and provides
    /// continuous price signals. Capped at 64× to avoid astronomical fees.
    pub fn effective_min_fee_rate(&self) -> f64 {
        let count = self.count();
        let utilization = if MAX_MEMPOOL_SIZE > 0 {
            count as f64 / MAX_MEMPOOL_SIZE as f64
        } else {
            0.0
        };

        // Exponential: 2^(utilization × 6)
        // At 0%: 2^0 = 1×, at 50%: 2^3 = 8×, at 100%: 2^6 = 64×
        let multiplier = if utilization < 0.001 {
            1.0
        } else {
            (2.0_f64).powf(utilization * 6.0).min(64.0)
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

    /// Minimum fee rate in the pool (the lowest fee-rate TX). Returns 0 if pool is empty.
    /// The fee index is sorted ascending by `u64::MAX - fee_rate`, so the *last*
    /// entry is the lowest fee rate.
    pub fn pool_min_fee(&self) -> u64 {
        // Reverse-seek to the last fee-index key (lowest fee_rate) in O(1)
        let past_end = b"fee;";
        let mut iter = self.db.iterator(
            rocksdb::IteratorMode::From(past_end, rocksdb::Direction::Reverse),
        );
        match iter.next() {
            Some(Ok((k, _))) if k.starts_with(PFX_FEE) => {
                // Key format: "fee:{inverted_fee_rate:020}:{hash}"
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
        Self::try_new(source).inspect_err(|e| {
            slog_error!("mempool", "storage_unavailable", error => &e.to_string());
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
        Ok(Self { db, network: NetworkMode::Mainnet })
    }

    /// Create a mempool with explicit network mode for correct signature verification.
    pub fn new_with_network<S: Into<SharedDbSource>>(source: S, network: NetworkMode) -> Result<Self, MempoolError> {
        let mut m = Self::new(source)?;
        m.network = network;
        Ok(m)
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
        let tx_size = tx.canonical_bytes().len().max(1) as u64;
        let fee_rate = tx.fee / tx_size;
        let fee_key = format!("fee:{:020}:{}", u64::MAX - fee_rate, tx.hash);
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
                batch.put(format!("rdep:{}:{}:{}", input.txid, input.index, tx.hash).as_bytes(), b"1");
            }
        }
        self.db.write(batch).is_ok()
    }

    pub fn add_transaction(&self, tx: &Transaction) -> bool {
        // ── L0 Coinbase rejection: coinbase TXs are created by miners,
        // never relayed via mempool. Accepting them would let an attacker
        // inject free-money TXs that pass `is_coinbase()` checks. ─────
        if tx.is_coinbase() {
            return false;
        }

        // ── L1 Network: cheap sanity (no crypto, no DB) ──────────────
        if tx.canonical_bytes().len() > MAX_TX_BYTE_SIZE {
            return false;
        }
        if tx.inputs.is_empty() {
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

        // ── L1.6  Swap/DEX-specific validation ─────────────────────────
        if tx.tx_type == TxType::SwapTx {
            // SwapTx requires 2x minimum fee due to HTLC overhead
            if tx.fee < MIN_RELAY_FEE * 2 {
                return false;
            }
            // Must have HTLC secret hash in payload
            if tx.payload_hash.is_none() {
                return false;
            }
        }
        if tx.tx_type == TxType::DexOrder {
            // DexOrder requires 1.5x minimum fee
            let dex_min_fee = MIN_RELAY_FEE + MIN_RELAY_FEE / 2;
            if tx.fee < dex_min_fee {
                return false;
            }
            // Must have order data in payload
            if tx.payload_hash.is_none() {
                return false;
            }
        }

        // ── L1.7 Contract TX validation ────────────────────────────────
        if tx.tx_type == TxType::ContractCreate {
            // Must have deploy code
            if tx.deploy_code.is_none() && tx.payload_hash.is_none() {
                return false;
            }
            // Must have gas_limit
            if tx.gas_limit.unwrap_or(0) == 0 {
                return false;
            }
            // Intrinsic gas check: base cost + per-byte cost
            let code_len = tx.deploy_code.as_ref().map(|c| c.len()).unwrap_or(0) as u64;
            let intrinsic_gas = 32_000 + code_len * 200; // CREATE base + per-byte
            if tx.gas_limit.unwrap_or(0) < intrinsic_gas {
                return false;
            }
            // Must have sufficient fee to cover gas
            let min_fee = tx.gas_limit.unwrap_or(0) / 1000; // 0.1% of gas as minimum fee
            if tx.fee < min_fee.max(MIN_RELAY_FEE) {
                return false;
            }
        }
        if tx.tx_type == TxType::ContractCall {
            // Must have target contract address
            if tx.contract_address.is_none() {
                return false;
            }
            // Must have gas_limit
            if tx.gas_limit.unwrap_or(0) == 0 {
                return false;
            }
            // Minimum fee
            let min_fee = tx.gas_limit.unwrap_or(0) / 1000;
            if tx.fee < min_fee.max(MIN_RELAY_FEE) {
                return false;
            }
        }

        // ── L2 Structural: signature verification (prevents flood) ───
        if !tx.is_coinbase()
            && !TxValidator::verify_signatures_for_network(tx, &self.network) {
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
        // Checks ALL unique owners across inputs to prevent bypass via
        // multi-owner transactions.
        for sender in Self::tx_senders(tx) {
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

            // Build confirmed UTXO keys: only include inputs whose parent TX
            // is NOT in the mempool (i.e., the UTXO is confirmed on-chain).
            // Previously this used all of tx.inputs, which was circular —
            // it treated every input the new TX spends as "confirmed",
            // effectively disabling RBF Rule 5 (no new unconfirmed inputs).
            let confirmed_keys: std::collections::HashSet<String> = tx.inputs.iter()
                .filter_map(|inp| {
                    let key = crate::domain::utxo::utxo_set::utxo_key(&inp.txid, inp.index)
                        .ok()
                        .map(|k| k.to_string())?;
                    // If the parent TX exists in the mempool, the input is unconfirmed
                    let parent_key = format!("tx:{}", inp.txid);
                    if matches!(self.db.get(parent_key.as_bytes()), Ok(Some(_))) {
                        None // unconfirmed — parent is still in mempool
                    } else {
                        Some(key) // confirmed — parent not in mempool
                    }
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

        let tx_size = tx.canonical_bytes().len().max(1) as u64;
        let fee_rate = tx.fee / tx_size;
        let fee_key = format!("fee:{:020}:{}", u64::MAX - fee_rate, tx.hash);
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

                let dep_rev = format!("rdep:{}:{}:{}", input.txid, input.index, tx.hash);
                batch.put(dep_rev.as_bytes(), b"1");
            }
        }

        // Sender index for per-address anti-spam (all unique owners)
        for sender in Self::tx_senders(tx) {
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
            // that this tx depends on, and another pool tx also spends it.
            // Include the output index so two children spending DIFFERENT
            // outputs of the same parent are not falsely flagged as conflicts.
            let rdep_prefix = format!("rdep:{}:{}:", input.txid, input.index);
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
        // BUG FIX: Collect into a HashSet first to deduplicate.
        // A child TX that spends multiple outputs of the same parent
        // produces multiple rdep keys (one per output), resulting in
        // duplicate child hashes. Dedup prevents double-eviction in
        // RBF and cascade removal.
        let set: HashSet<String> = self.db
            .prefix_iterator(prefix.as_bytes())
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(&prefix_bytes))
            .filter_map(|(k, _)| {
                // Key format: "rdep:{parent_txid}:{output_index}:{child_txid}"
                // After stripping "rdep:{parent_txid}:", remainder is "{output_index}:{child_txid}"
                String::from_utf8(k.to_vec()).ok()
                    .and_then(|s| s.strip_prefix(&prefix).map(|p| p.to_string()))
                    .and_then(|remainder| {
                        // Split on first ':' to separate output_index from child_txid
                        remainder.split_once(':').map(|(_, child)| child.to_string())
                    })
            })
            .collect();
        set.into_iter().collect()
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
        // BUG FIX: Cascade removal to dependent transactions (children that
        // spend this TX's outputs). Without this, removing a parent leaves
        // orphaned children in the pool whose inputs no longer exist,
        // causing block template validation failures.
        let dependents = self.get_dependents(txid);
        for dep_txid in &dependents {
            // Recursive call handles transitive dependents (grandchildren, etc.)
            self.remove_transaction(dep_txid);
        }

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

            // Clean up sender index for ALL owners (not just the first)
            for sender in Self::tx_senders(&tx) {
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
                Err(e) => {
                    slog_error!("mempool", "remove_transaction_write_failed",
                        txid => txid, error => e);
                }
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

    pub fn select_transactions_for_block(
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
        // Only delete keys with mempool-specific prefixes to avoid
        // destroying non-mempool data in a shared DB.
        const MEMPOOL_PREFIXES: &[&[u8]] = &[
            b"tx:", b"fee:", b"inp:", b"dep:", b"rdep:", b"sender:", b"_meta:",
            b"orphan:", b"orphan_ts:",
        ];

        let mempool_keys: Vec<Vec<u8>> = self.db
            .iterator(rocksdb::IteratorMode::Start)
            .filter_map(|r| r.ok())
            .filter(|(k, _)| MEMPOOL_PREFIXES.iter().any(|pfx| k.starts_with(pfx)))
            .map(|(k, _)| k.to_vec())
            .collect();
        for k in &mempool_keys {
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
        // Coinbase transactions are miner-created; they must never enter the mempool.
        if tx.is_coinbase() {
            return Err(MempoolError::ValidationFailed(
                "coinbase transactions cannot enter the mempool".to_string()
            ));
        }

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

        // Swap/DEX-specific validation
        if tx.tx_type == TxType::SwapTx {
            if tx.fee < MIN_RELAY_FEE * 2 {
                return Err(MempoolError::FeeTooLow { fee: tx.fee, minimum: MIN_RELAY_FEE * 2 });
            }
            if tx.payload_hash.is_none() {
                return Err(MempoolError::ValidationFailed("SwapTx missing HTLC secret hash".into()));
            }
        }
        if tx.tx_type == TxType::DexOrder {
            let dex_min_fee = MIN_RELAY_FEE + MIN_RELAY_FEE / 2;
            if tx.fee < dex_min_fee {
                return Err(MempoolError::FeeTooLow { fee: tx.fee, minimum: dex_min_fee });
            }
            if tx.payload_hash.is_none() {
                return Err(MempoolError::ValidationFailed("DexOrder missing order payload".into()));
            }
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

        // Per-sender anti-spam: reject if ANY sender already has MAX_TXS_PER_SENDER in pool.
        // BUG FIX: Previously used tx_sender() which only checks the first input owner.
        // A multi-input TX with owners [A, B] would bypass the limit for owner B.
        // Now uses tx_senders() (all unique owners) consistent with add_transaction().
        for sender in Self::tx_senders(tx) {
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
                total_fee = total_fee.saturating_add(tx.fee);
                total_size = total_size.saturating_add(tx.canonical_bytes().len() as u64);
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
                total_fee  = total_fee.saturating_add(tx.fee);
                total_size = total_size.saturating_add(tx.canonical_bytes().len() as u64);
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
                total_fee = total_fee.saturating_add(tx.fee);
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
        self.select_transactions_for_block(utxo_set, max_count)
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
            ..Default::default()
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
            ..Default::default()
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
            let tx_size = old_tx.canonical_bytes().len().max(1) as u64;
            let fee_rate = old_tx.fee / tx_size;
            let fee_key = format!("fee:{:020}:{}", u64::MAX - fee_rate, old_hash);
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
        // Simulate 75% utilization: exponential curve should give ~22.6×
        mp.meta_set_u64(META_TX_COUNT, 75_000);
        let rate = mp.effective_min_fee_rate();
        assert!(
            rate > MIN_FEE_RATE * 10.0 && rate < MIN_FEE_RATE * 40.0,
            "75% utilization should give ~22.6× rate, got {}",
            rate
        );
    }

    #[test]
    fn surge_pricing_high_at_90_percent() {
        let mp = pool("surge_max");
        mp.meta_set_u64(META_TX_COUNT, 95_000);
        let rate = mp.effective_min_fee_rate();
        assert!(
            rate > MIN_FEE_RATE * 20.0,
            "95% utilization should give high rate, got {}",
            rate
        );
        assert!(
            rate <= MIN_FEE_RATE * 64.0,
            "Rate should be capped at 64×, got {}",
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
                let ok = self.db.put(key.as_bytes(), &data).is_ok();
                if ok {
                    // Store receive time (wall clock) for age-based eviction.
                    // This is tamper-proof unlike tx.timestamp which is sender-set.
                    let receive_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let ts_key = format!("orphan_ts:{}", tx.hash);
                    let _ = self.db.put(ts_key.as_bytes(), receive_time.to_le_bytes());
                }
                ok
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
                    slog_warn!("mempool", "orphan_db_delete_failed", key => &key, error => &e.to_string());
                }
                // Also clean up the receive-time metadata key so it doesn't
                // leak in the DB after promotion.
                let ts_key = format!("orphan_ts:{}", orphan.hash);
                let _ = self.db.delete(ts_key.as_bytes());
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
            slog_warn!("mempool", "orphan_db_delete_failed", key => &key, error => &e.to_string());
        }
        // Also clean up the receive-time metadata key
        let ts_key = format!("orphan_ts:{}", tx_hash);
        let _ = self.db.delete(ts_key.as_bytes());
    }

    pub fn prune_orphans(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // BUG FIX: Use the receive-time metadata key (orphan_ts:{hash}) instead
        // of tx.timestamp.  tx.timestamp is set by the sender and can be
        // arbitrarily far in the past or future, so using it for age-based
        // eviction lets an attacker craft TXs that either never expire
        // (future timestamp) or get instantly pruned (stale timestamp).
        // The receive-time is the wall-clock time at which add_orphan stored
        // the TX, which is tamper-proof.
        let stale_keys: Vec<Vec<u8>> = self.db
            .prefix_iterator(PFX_ORPHAN)
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(PFX_ORPHAN))
            .filter_map(|(k, _)| {
                // Extract hash from key "orphan:{hash}"
                let key_str = String::from_utf8(k.to_vec()).ok()?;
                let hash = key_str.strip_prefix("orphan:")?;
                let ts_key = format!("orphan_ts:{}", hash);
                let receive_time = match self.db.get(ts_key.as_bytes()) {
                    Ok(Some(v)) if v.len() >= 8 => {
                        let mut buf = [0u8; 8];
                        buf.copy_from_slice(&v[..8]);
                        u64::from_le_bytes(buf)
                    }
                    _ => {
                        // No receive-time recorded (legacy entry) — fall back to
                        // tx.timestamp so old entries still get pruned eventually.
                        let tx: Transaction = bincode::deserialize(
                            &self.db.get(&k).ok()??
                        ).ok()?;
                        tx.timestamp
                    }
                };
                if now.saturating_sub(receive_time) > MAX_ORPHAN_AGE_SECS {
                    Some(k.to_vec())
                } else {
                    None
                }
            })
            .collect();

        for k in &stale_keys {
            let label = String::from_utf8_lossy(k);
            if let Err(e) = self.db.delete(k) {
                slog_warn!("mempool", "orphan_db_delete_failed", key => &label.to_string(), error => &e.to_string());
            }
            // Clean up the receive-time metadata key
            if let Ok(key_str) = String::from_utf8(k.to_vec()) {
                if let Some(hash) = key_str.strip_prefix("orphan:") {
                    let ts_key = format!("orphan_ts:{}", hash);
                    let _ = self.db.delete(ts_key.as_bytes());
                }
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
            ..Default::default()
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
