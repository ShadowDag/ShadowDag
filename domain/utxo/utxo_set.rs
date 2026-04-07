// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::sync::Arc;
use std::collections::HashMap; // 🔥 ADD
use parking_lot::RwLock;       // 🔥 ADD

use crate::domain::block::block::Block;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::transaction::tx_validator::TxValidator;
use crate::domain::transaction::tx_hash::TxHash;
use crate::domain::utxo::utxo::Utxo;
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_validator::UtxoValidator;
use crate::domain::traits::utxo_backend::{UtxoBackend, BatchWrite};
use crate::errors::StorageError;
use crate::slog_warn;

/// Coinbase maturity — MUST match ConsensusParams::COINBASE_MATURITY.
/// At 10 BPS, 1000 blocks = 100 seconds = safe against DAG reorgs.
pub const COINBASE_MATURITY: u64 = crate::config::consensus::consensus_params::ConsensusParams::COINBASE_MATURITY;

/// Single source of truth for UTXO key construction.
///
/// CONSENSUS CRITICAL: returns a canonical 36-byte binary key.
///   bytes[0..32]  = SHA-256 tx hash decoded from hex (big-endian)
///   bytes[32..36] = output index as big-endian u32
///
/// ALL UTXO operations MUST use this function.  Any deviation → fork.
///
/// Returns `Err` on malformed hashes instead of panicking — safe for
/// untrusted network input.  Callers propagate via `?`.
#[inline]
pub fn utxo_key(tx_hash: &str, index: u32) -> Result<UtxoKey, StorageError> {
    UtxoKey::try_new(tx_hash, index).ok_or_else(|| {
        StorageError::Other(format!(
            "invalid tx hash for UtxoKey (must be 64 hex chars, got '{}...')",
            &tx_hash[..tx_hash.len().min(24)]
        ))
    })
}

/// Convert an arbitrary short name to a deterministic 64-char hex hash.
///
/// For use in tests ONLY — maps names like "tx1", "abc" to valid SHA-256 hex
/// strings that pass UtxoKey strict validation.
///
/// NOT consensus code — never call in production paths.
#[cfg(test)]
pub fn test_hash(name: &str) -> String {
    use sha2::{Sha256, Digest};
    hex::encode(Sha256::digest(name.as_bytes()))
}

/// Undo data for a single block — everything needed to reverse its UTXO changes.
/// Stored atomically alongside the UTXO changes in the same WriteBatch.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BlockUndoData {
    /// UTXOs that were spent by this block (key → full Utxo before spending).
    /// On rollback: restore these as unspent.
    pub spent_utxos: Vec<(String, Utxo)>,
    /// UTXO keys that were created by this block.
    /// On rollback: delete these.
    pub created_keys: Vec<String>,
    /// Address index entries created (addr_key → utxo_key).
    /// On rollback: delete these.
    pub created_addr_indexes: Vec<(String, String)>,
    /// Address index entries deleted (addr_key → utxo_key).
    /// On rollback: restore these.
    pub deleted_addr_indexes: Vec<(String, String)>,
    /// Coinbase height metadata keys created.
    /// On rollback: delete these.
    pub created_cb_heights: Vec<String>,
    /// Transaction IDs that were applied (not skipped) by this block.
    /// On rollback: remove from tx_seen index so they can be re-applied
    /// by a different chain during reorg.
    #[serde(default)]
    pub applied_tx_ids: Vec<String>,
}

/// Maximum UTXO cache entries (prevents unbounded memory growth)
const MAX_CACHE_SIZE: usize = 500_000;

/// Eviction batch when cache is full
const CACHE_EVICT_BATCH: usize = 50_000;

/// Warning threshold for total UTXO set size in the database.
/// When the UTXO set exceeds this count, a warning is logged to alert
/// operators about potential resource pressure. This is NOT a hard limit
/// (rejecting valid blocks would break consensus), but a monitoring signal.
#[allow(dead_code)]
pub const UTXO_SET_WARNING_THRESHOLD: usize = 50_000_000;

pub struct UtxoSet {
    store: Arc<dyn UtxoBackend>,
    cache: RwLock<HashMap<UtxoKey, Utxo>>,
}

impl UtxoSet {
    pub fn new(store: Arc<dyn UtxoBackend>) -> Self {
        Self {
            store,
            cache: RwLock::new(HashMap::with_capacity(MAX_CACHE_SIZE / 4)),
        }
    }

    pub fn add_utxo(&self, key: &UtxoKey, owner: String, amount: u64, address: String) {
        let utxo = Utxo {
            owner,
            amount,
            address,
            spent: false,
        };

        // WRITE STORE FIRST — if it fails, cache stays clean (no desync)
        let store_ok = self.store.add_utxo(key, &utxo).is_ok();

        if store_ok {
            let mut cache = self.cache.write();
            if cache.len() >= MAX_CACHE_SIZE {
                // Deterministic eviction: sort keys (binary ordering = deterministic).
                let mut keys: Vec<UtxoKey> = cache.keys().copied().collect();
                keys.sort_unstable();
                let evict_count = CACHE_EVICT_BATCH.min(keys.len());
                for k in keys.into_iter().take(evict_count) {
                    cache.remove(&k);
                }
            }
            cache.insert(*key, utxo);
        } else {
            slog_warn!("utxo", "store_write_failed", key => &key.to_string());
        }
    }

    pub fn add_utxo_coinbase(
        &self,
        key: &UtxoKey,
        owner: String,
        amount: u64,
        address: String,
        created_height: u64,
    ) {
        let utxo = Utxo {
            owner,
            amount,
            address,
            spent: false,
        };

        // DB FIRST — cache only updated after successful store write
        let store_ok = self.store.add_utxo(key, &utxo).is_ok();

        // Metadata key: "cb_height:" + 36 binary bytes
        let mut meta_key = Vec::with_capacity(10 + 36);
        meta_key.extend_from_slice(b"cb_height:");
        meta_key.extend_from_slice(key.as_bytes());

        if store_ok {
            let _ = self.store.put_raw(&meta_key, &created_height.to_le_bytes());
            let mut cache = self.cache.write();
            if cache.len() >= MAX_CACHE_SIZE {
                let mut keys: Vec<UtxoKey> = cache.keys().copied().collect();
                keys.sort_unstable();
                for k in keys.into_iter().take(CACHE_EVICT_BATCH) {
                    cache.remove(&k);
                }
            }
            cache.insert(*key, utxo);
        } else {
            slog_warn!("utxo", "coinbase_store_write_failed", key => &key.to_string());
        }
    }

    pub fn get_utxo(&self, key: &UtxoKey) -> Option<Utxo> {
        // CACHE FIRST
        if let Some(u) = self.cache.read().get(key) {
            return Some(u.clone());
        }

        let res = self.store.get_utxo(key).ok().flatten();

        if let Some(ref u) = res {
            self.cache.write().insert(*key, u.clone());
        }

        res
    }

    pub fn spend_utxo(&self, key: &UtxoKey) {
        if let Some(u) = self.cache.write().get_mut(key) {
            u.spent = true; // 🔥 cache update
        }
        let _ = self.store.spend_utxo(key);
    }

    pub fn spend_utxo_checked(&self, key: &UtxoKey, current_height: u64) -> Result<(), StorageError> {
        let utxo = self
            .get_utxo(key) // 🔥 use cache-aware
            .ok_or_else(|| StorageError::KeyNotFound(format!("utxo {} not found", key)))?;

        if utxo.spent {
            return Err(StorageError::Other(format!("utxo {} already spent", key)));
        }

        if let Some(created_height) = self.coinbase_created_height(key) {
            let confirmations = current_height.saturating_sub(created_height);
            if confirmations < COINBASE_MATURITY {
                return Err(StorageError::Other(format!(
                    "coinbase utxo {} immature: {} confirmations < required {}",
                    key, confirmations, COINBASE_MATURITY
                )));
            }
        }

        self.spend_utxo(key); // 🔥 reuse
        Ok(())
    }

    pub fn exists_spendable(&self, key: &UtxoKey, current_height: u64) -> bool {
        match self.get_utxo(key) {
            Some(utxo) if !utxo.spent => {
                if let Some(created_height) = self.coinbase_created_height(key) {
                    current_height.saturating_sub(created_height) >= COINBASE_MATURITY
                } else {
                    true
                }
            }
            _ => false,
        }
    }

    pub fn exists(&self, key: &UtxoKey) -> bool {
        matches!(self.get_utxo(key), Some(utxo) if !utxo.spent)
    }

    pub fn get_balance(&self, address: &str) -> u64 {
        self.store.get_balance(address).unwrap_or(0)
    }

    pub fn export_all(&self) -> Vec<(UtxoKey, Utxo)> {
        self.store.export_all().unwrap_or_else(|_| Vec::new())
    }

    /// Count unspent UTXOs in the backing store.
    /// Used by crash recovery to detect empty UTXO state.
    pub fn count_utxos(&self) -> usize {
        self.store.count_utxos()
    }

    /// Prune spent UTXOs from the backing store to reclaim disk space.
    /// Spent UTXOs are kept for a maturity window for reorg safety,
    /// then can be safely deleted. Returns the number pruned.
    pub fn prune_spent_utxos(&self) -> Result<u64, crate::errors::StorageError> {
        self.store.prune_spent()
    }

    /// Compact the underlying RocksDB to reclaim disk space after pruning.
    pub fn compact(&self) {
        self.store.compact();
    }

    /// Clear all UTXO data (cache + DB). Used by crash recovery before replay.
    pub fn clear_all(&self) {
        // Clear in-memory cache
        self.cache.write().clear();
        // Clear DB via store
        self.store.clear_all();
    }

    /// Apply a block's transactions to the UTXO set.
    ///
    /// Accepts a full `Block` reference so that `validate_block_utxos` can be
    /// called as the single unified validation entry point before the atomic write.
    pub fn apply_block_full(&self, block: &Block, block_height: u64) -> Result<(), StorageError> {
        // Unified validation — ONE place for all UTXO validation logic
        UtxoValidator::validate_block_utxos(block, self, block_height)?;
        self.apply_block_write(&block.body.transactions, block_height)
    }

    pub fn apply_block(&self, transactions: &[Transaction], block_height: u64) -> Result<(), StorageError> {
        // Build a temporary Block for the unified validator
        let block = Block {
            header: crate::domain::block::block_header::BlockHeader {
                version: 0,
                hash: String::new(),
                parents: Vec::new(),
                merkle_root: String::new(),
                timestamp: 0,
                nonce: 0,
                difficulty: 0,
                height: block_height,
                blue_score: 0,
                selected_parent: None,
                utxo_commitment: None,
                extra_nonce: 0,
            },
            body: crate::domain::block::block_body::BlockBody {
                transactions: transactions.to_vec(),
            },
        };

        // Unified validation — ONE place for all UTXO validation logic
        UtxoValidator::validate_block_utxos(&block, self, block_height)?;
        self.apply_block_write(transactions, block_height)
    }

    /// Internal: perform the UTXO write after validation has passed.
    /// STRICT: any failure (DB access, serialization) returns Err immediately.
    /// No silent success. No partial writes. All or nothing.
    /// Apply block's UTXO changes atomically with:
    ///   - Conflict detection (optimistic concurrency — no global lock)
    ///   - Undo data (for reorg rollback)
    ///   - Commitment hash (for recovery verification)
    ///
    /// All written in a SINGLE WriteBatch (all-or-nothing).
    pub fn apply_block_write_with_commitment(
        &self,
        transactions: &[Transaction],
        block_height: u64,
        block_hash: &str,
    ) -> Result<String, StorageError> {
        use sha2::{Sha256, Digest};

        let mut ops: Vec<BatchWrite> = Vec::new();

        // Undo data — collects everything needed to reverse this block
        let mut undo = BlockUndoData {
            spent_utxos: Vec::new(),
            created_keys: Vec::new(),
            created_addr_indexes: Vec::new(),
            deleted_addr_indexes: Vec::new(),
            created_cb_heights: Vec::new(),
            applied_tx_ids: Vec::new(),
        };

        // Incremental commitment hash chain
        let mut commitment_hasher = Sha256::new();
        let prev_commitment_key = "utxo:latest_commitment";
        if let Some(prev) = self.store.get_raw(prev_commitment_key.as_bytes()) {
            commitment_hasher.update(&prev);
        }
        commitment_hasher.update(block_hash.as_bytes());
        commitment_hasher.update(block_height.to_le_bytes());

        for tx in transactions {
            if tx.is_coinbase() {
                for (idx, output) in tx.outputs.iter().enumerate() {
                    // CANONICAL binary UtxoKey — same format as apply_block_dag_ordered.
                    // Previously used string "txhash:index" which produced DIFFERENT
                    // bytes than UtxoKey's 36-byte binary encoding → key mismatch on spend.
                    let key = utxo_key(&tx.hash, idx as u32)?;

                    let addr = output.address.clone();
                    let utxo = crate::domain::utxo::utxo::Utxo::new(
                        addr.clone(), addr, output.amount,
                    );
                    let data = bincode::serialize(&utxo)
                        .map_err(|e| StorageError::Serialization(format!("coinbase UTXO {}: {}", key, e)))?;
                    ops.push(BatchWrite::Put { key: key.as_ref().to_vec(), value: data });

                    let key_str = key.to_string();
                    let addr_key = format!("addr:{}:{}", output.address, key_str);
                    ops.push(BatchWrite::Put { key: addr_key.as_bytes().to_vec(), value: key.as_ref().to_vec() });

                    let mut meta_key_bytes = b"cb_height:".to_vec();
                    meta_key_bytes.extend_from_slice(key.as_ref());
                    ops.push(BatchWrite::Put { key: meta_key_bytes.clone(), value: block_height.to_le_bytes().to_vec() });

                    // Track for undo
                    undo.created_keys.push(key_str.clone());
                    undo.created_addr_indexes.push((addr_key, key_str.clone()));
                    undo.created_cb_heights.push(format!("cb_height:{}", key));

                    commitment_hasher.update(b"C");
                    commitment_hasher.update(key.as_ref());
                    commitment_hasher.update(output.address.as_bytes());
                    commitment_hasher.update(output.amount.to_le_bytes());
                }
            } else {
                for input in &tx.inputs {
                    let key = utxo_key(&input.txid, input.index)?;

                    // CONFLICT DETECTION: read from DB (not cache) for latest state
                    let raw = self.store.get_raw(key.as_ref())
                        .ok_or_else(|| StorageError::KeyNotFound(format!("UTXO_CONFLICT: {} not found at write time", key)))?;
                    let mut utxo: crate::domain::utxo::utxo::Utxo = bincode::deserialize(&raw)
                        .map_err(|e| StorageError::Serialization(format!("conflict check deserialize {}: {}", key, e)))?;

                    if utxo.spent {
                        return Err(StorageError::Other(format!(
                            "UTXO_CONFLICT: {} already spent (concurrent block won)", key
                        )));
                    }

                    // Save pre-spend state for undo
                    let key_str = key.to_string();
                    undo.spent_utxos.push((key_str.clone(), utxo.clone()));

                    let addr_key = format!("addr:{}:{}", utxo.address, key);
                    ops.push(BatchWrite::Delete { key: addr_key.as_bytes().to_vec() });
                    undo.deleted_addr_indexes.push((addr_key, key_str));

                    commitment_hasher.update(b"S");
                    commitment_hasher.update(key.as_ref());
                    commitment_hasher.update(utxo.amount.to_le_bytes());

                    utxo.spent = true;
                    let data = bincode::serialize(&utxo)
                        .map_err(|e| StorageError::Serialization(format!("spent UTXO {}: {}", key, e)))?;
                    ops.push(BatchWrite::Put { key: key.as_ref().to_vec(), value: data });
                }

                for (idx, output) in tx.outputs.iter().enumerate() {
                    // CANONICAL binary UtxoKey — same format as apply_block_dag_ordered.
                    let key = utxo_key(&tx.hash, idx as u32)?;

                    let addr = output.address.clone();
                    let utxo = crate::domain::utxo::utxo::Utxo::new(
                        addr.clone(), addr, output.amount,
                    );
                    let data = bincode::serialize(&utxo)
                        .map_err(|e| StorageError::Serialization(format!("output UTXO {}: {}", key, e)))?;
                    ops.push(BatchWrite::Put { key: key.as_ref().to_vec(), value: data });

                    let key_str = key.to_string();
                    let addr_key = format!("addr:{}:{}", output.address, key_str);
                    ops.push(BatchWrite::Put { key: addr_key.as_bytes().to_vec(), value: key.as_ref().to_vec() });

                    // Track for undo
                    undo.created_keys.push(key_str.clone());
                    undo.created_addr_indexes.push((addr_key, key_str));

                    commitment_hasher.update(b"C");
                    commitment_hasher.update(key.as_ref());
                    commitment_hasher.update(output.address.as_bytes());
                    commitment_hasher.update(output.amount.to_le_bytes());
                }
            }
        }

        // Commitment
        let commitment = format!("{:x}", commitment_hasher.finalize());
        let commit_key = format!("utxo:commitment:{}", block_hash);
        ops.push(BatchWrite::Put { key: commit_key.as_bytes().to_vec(), value: commitment.as_bytes().to_vec() });
        ops.push(BatchWrite::Put { key: prev_commitment_key.as_bytes().to_vec(), value: commitment.as_bytes().to_vec() });

        // Store undo data in SAME batch — atomic with UTXO changes
        let undo_key = format!("utxo:undo:{}", block_hash);
        let undo_data = bincode::serialize(&undo)
            .map_err(|e| StorageError::Serialization(format!("undo data: {}", e)))?;
        ops.push(BatchWrite::Put { key: undo_key.as_bytes().to_vec(), value: undo_data });

        // ATOMIC COMMIT — UTXO + commitment + undo = all or nothing
        self.store.write_batch(ops).map_err(|e| StorageError::WriteFailed(format!("apply_block atomic write: {}", e)))?;

        // Update cache after successful DB write
        for tx in transactions {
            for input in &tx.inputs {
                if let Ok(key) = utxo_key(&input.txid, input.index) {
                    if let Some(u) = self.cache.write().get_mut(&key) {
                        u.spent = true;
                    }
                }
            }
        }

        Ok(commitment)
    }

    /// DAG-aware UTXO execution: apply non-conflicting txs, skip conflicts.
    ///
    /// ═══════════════════════════════════════════════════════════════
    /// CONSENSUS RULE: DETERMINISTIC EXECUTION ORDER
    ///
    /// Transactions are executed in STRICT SEQUENTIAL ORDER as they
    /// appear in block.body.transactions[]. This is a consensus rule:
    ///
    ///   - Same block = same tx order = same execution on ALL nodes
    ///   - First valid tx wins any UTXO conflict
    ///   - Later conflicting txs are SKIPPED (deterministically)
    ///   - NO parallel execution, NO reordering, NO randomness
    ///
    /// Skipped transactions:
    ///   - Do NOT modify UTXO state
    ///   - Do NOT contribute fees to coinbase
    ///   - Remain in the block body (for structural integrity)
    ///   - Are recorded in the commitment hash (as "SKIP" markers)
    ///
    /// This ensures every node computes identical state from the
    /// same block, regardless of when the block was received.
    /// ═══════════════════════════════════════════════════════════════
    ///
    /// Returns: (applied_count, skipped_count, applied_fees)
    ///
    /// applied_fees = sum of fees from txs that were actually applied
    /// (excludes skipped/duplicate txs). Used for coinbase validation.
    pub fn apply_block_dag_ordered(
        &self,
        transactions: &[Transaction],
        block_height: u64,
        block_hash: &str,
    ) -> Result<(usize, usize, u64), StorageError> {
        use sha2::{Sha256, Digest};

        let mut ops: Vec<BatchWrite> = Vec::new();
        let mut undo = BlockUndoData {
            spent_utxos: Vec::new(),
            created_keys: Vec::new(),
            created_addr_indexes: Vec::new(),
            deleted_addr_indexes: Vec::new(),
            created_cb_heights: Vec::new(),
            applied_tx_ids: Vec::new(),
        };

        let mut commitment_hasher = Sha256::new();
        let prev_commitment_key = "utxo:latest_commitment";
        if let Some(prev) = self.store.get_raw(prev_commitment_key.as_bytes()) {
            commitment_hasher.update(&prev);
        }
        commitment_hasher.update(block_hash.as_bytes());
        commitment_hasher.update(block_height.to_le_bytes());

        let mut applied = 0usize;
        let mut skipped = 0usize;
        let mut applied_fees: u64 = 0;

        // Staged state for intra-block visibility:
        // - staged_outputs: outputs created by earlier txs in THIS block
        //   (not yet in DB because WriteBatch hasn't committed)
        // - staged_spent: inputs spent by earlier txs in THIS block
        //
        // Input lookup order: staged_spent → DB → staged_outputs
        // This ensures tx3 can see tx1's output even though it's only in the batch.
        let mut staged_outputs: HashMap<UtxoKey, crate::domain::utxo::utxo::Utxo> =
            HashMap::new();
        let mut staged_spent: std::collections::HashSet<UtxoKey> =
            std::collections::HashSet::new();

        for tx in transactions {
            // ───────────────────────────────────────────────────────────
            // TX UNIQUENESS CHECK (consensus rule)
            //
            // Reject duplicate tx across the active DAG. Same tx in
            // multiple blocks = spam/replay. Coinbase txs are exempt
            // because they're unique per block by construction (include
            // block hash/height in their hash).
            //
            // Key: "tx_seen:{tx_id}" — stored in same DB, same WriteBatch.
            // On rollback: removed (allows re-application on new chain).
            // ───────────────────────────────────────────────────────────
            if !tx.is_coinbase() {
                let seen_key = format!("tx_seen:{}", tx.hash);
                if self.store.get_raw(seen_key.as_bytes()).is_some() {
                    // Already applied by an earlier block → skip as duplicate
                    skipped += 1;
                    commitment_hasher.update(b"DUP");
                    commitment_hasher.update(tx.hash.as_bytes());
                    continue;
                }
            }

            if tx.is_coinbase() {
                for (idx, output) in tx.outputs.iter().enumerate() {
                    let key = utxo_key(&tx.hash, idx as u32)?;
                    let addr = output.address.clone();
                    let utxo = crate::domain::utxo::utxo::Utxo::new(
                        addr.clone(), addr, output.amount,
                    );
                    let data = bincode::serialize(&utxo)
                        .map_err(|e| StorageError::Serialization(format!("coinbase UTXO {}: {}", key, e)))?;
                    ops.push(BatchWrite::Put { key: key.as_ref().to_vec(), value: data });
                    let key_str = key.to_string();
                    let addr_key = format!("addr:{}:{}", output.address, key_str);
                    ops.push(BatchWrite::Put { key: addr_key.as_bytes().to_vec(), value: key.as_ref().to_vec() });
                    let meta_key = "cb_height:".to_string();
                    let mut meta_key_bytes = meta_key.into_bytes();
                    meta_key_bytes.extend_from_slice(key.as_ref());
                    ops.push(BatchWrite::Put { key: meta_key_bytes.clone(), value: block_height.to_le_bytes().to_vec() });

                    undo.created_keys.push(key_str.clone());
                    undo.created_addr_indexes.push((addr_key, key_str));
                    let meta_key_string = format!("cb_height:{}", key);
                    undo.created_cb_heights.push(meta_key_string);

                    staged_outputs.insert(key, utxo);

                    commitment_hasher.update(b"C");
                    commitment_hasher.update(key.as_ref());
                    commitment_hasher.update(output.address.as_bytes());
                    commitment_hasher.update(output.amount.to_le_bytes());
                }
                applied += 1;
                continue;
            }

            // ───────────────────────────────────────────────────────
            // CONSENSUS RULE: Atomic per-tx execution
            //
            // Check ALL inputs BEFORE applying ANY. If any single
            // input is invalid → SKIP entire tx. No partial apply.
            //
            // Lookup order (critical for intra-block correctness):
            //   1. staged_spent → already consumed in this block → conflict
            //   2. staged_outputs → created by earlier tx in this block
            //   3. DB → committed state from previous blocks
            //   4. Not found anywhere → conflict
            //
            // staged_outputs MUST be checked BEFORE DB because
            // intra-block outputs only exist in staged state
            // (WriteBatch hasn't committed yet).
            // ───────────────────────────────────────────────────────
            let mut tx_inputs: Vec<(UtxoKey, crate::domain::utxo::utxo::Utxo)> = Vec::new();
            let mut conflict = false;

            for input in &tx.inputs {
                let key = utxo_key(&input.txid, input.index)?;

                // 1. Already spent by earlier tx in this block?
                if staged_spent.contains(&key) {
                    conflict = true;
                    break;
                }

                // 2. Created by earlier tx in this block? (intra-block spend)
                if let Some(utxo) = staged_outputs.get(&key) {
                    tx_inputs.push((key, utxo.clone()));
                    continue;
                }

                // 3. Exists in DB (committed state from previous blocks)?
                if let Some(raw) = self.store.get_raw(key.as_ref()) {
                    if let Ok(utxo) = bincode::deserialize::<crate::domain::utxo::utxo::Utxo>(&raw) {
                        if !utxo.spent {
                            tx_inputs.push((key, utxo));
                            continue;
                        }
                    }
                    // In DB but spent → conflict
                    conflict = true;
                    break;
                }

                // 4. Not found anywhere → conflict
                conflict = true;
                break;
            }

            if conflict {
                skipped += 1;
                commitment_hasher.update(b"SKIP");
                commitment_hasher.update(tx.hash.as_bytes());
                continue;
            }

            // ───────────────────────────────────────────────────────
            // CONSENSUS RULE: Signature + ownership + balance verification
            //
            // These checks MUST happen during execution (not just structural
            // validation) because intra-block UTXOs (staged_outputs) are only
            // visible here. Without these checks, a tx with forged signatures
            // or wrong ownership could be applied to the UTXO set.
            // ───────────────────────────────────────────────────────

            // A) Signature verification — every input must have a valid Ed25519 signature
            if !TxValidator::verify_signatures(tx) {
                skipped += 1;
                commitment_hasher.update(b"SKIP");
                commitment_hasher.update(tx.hash.as_bytes());
                continue;
            }

            // B) Ownership verification — input.owner must match UTXO address
            {
                let signing_msg = TxHash::signing_message(tx);
                let mut ownership_ok = true;
                for (i, input) in tx.inputs.iter().enumerate() {
                    let (ref _key, ref utxo) = tx_inputs[i];
                    if !TxValidator::verify_input_ownership_by_address(
                        input, &utxo.address, &signing_msg
                    ) {
                        ownership_ok = false;
                        break;
                    }
                }
                if !ownership_ok {
                    skipped += 1;
                    commitment_hasher.update(b"SKIP");
                    commitment_hasher.update(tx.hash.as_bytes());
                    continue;
                }
            }

            // C) Balance check — total inputs >= total outputs + fee
            {
                let input_sum: u64 = match tx_inputs.iter()
                    .map(|(_, u)| u.amount)
                    .try_fold(0u64, |a, b| a.checked_add(b))
                {
                    Some(s) => s,
                    None => {
                        skipped += 1;
                        commitment_hasher.update(b"SKIP");
                        commitment_hasher.update(tx.hash.as_bytes());
                        continue;
                    }
                };
                let output_sum: u64 = match tx.outputs.iter()
                    .map(|o| o.amount)
                    .try_fold(0u64, |a, b| a.checked_add(b))
                {
                    Some(s) => s,
                    None => {
                        skipped += 1;
                        commitment_hasher.update(b"SKIP");
                        commitment_hasher.update(tx.hash.as_bytes());
                        continue;
                    }
                };
                let total_required = match output_sum.checked_add(tx.fee) {
                    Some(s) => s,
                    None => {
                        skipped += 1;
                        commitment_hasher.update(b"SKIP");
                        commitment_hasher.update(tx.hash.as_bytes());
                        continue;
                    }
                };
                if input_sum < total_required {
                    skipped += 1;
                    commitment_hasher.update(b"SKIP");
                    commitment_hasher.update(tx.hash.as_bytes());
                    continue;
                }
            }

            // D) Coinbase maturity — coinbase outputs can't be spent until
            //    COINBASE_MATURITY blocks have passed
            {
                let mut maturity_ok = true;
                for (key, _) in &tx_inputs {
                    let mut meta_key = Vec::with_capacity(10 + 36);
                    meta_key.extend_from_slice(b"cb_height:");
                    meta_key.extend_from_slice(key.as_ref());
                    if let Some(raw) = self.store.get_raw(&meta_key) {
                        if raw.len() >= 8 {
                            let cb_h = u64::from_le_bytes(raw[..8].try_into().unwrap_or([0;8]));
                            if block_height < cb_h + COINBASE_MATURITY { // consensus maturity check
                                maturity_ok = false;
                                break;
                            }
                        }
                    }
                }
                if !maturity_ok {
                    skipped += 1;
                    commitment_hasher.update(b"SKIP");
                    commitment_hasher.update(tx.hash.as_bytes());
                    continue;
                }
            }

            // All inputs valid — apply this tx
            for (key, utxo) in &tx_inputs {
                let key_str = key.to_string();
                undo.spent_utxos.push((key_str.clone(), utxo.clone()));
                let addr_key = format!("addr:{}:{}", utxo.address, key_str);
                ops.push(BatchWrite::Delete { key: addr_key.as_bytes().to_vec() });
                undo.deleted_addr_indexes.push((addr_key, key_str));

                let mut spent_utxo = utxo.clone();
                spent_utxo.spent = true;
                let data = bincode::serialize(&spent_utxo)
                    .map_err(|e| StorageError::Serialization(format!("spent UTXO {}: {}", key, e)))?;
                ops.push(BatchWrite::Put { key: key.as_ref().to_vec(), value: data });

                // Mark as spent in staged state
                staged_spent.insert(*key);
                staged_outputs.remove(key);

                commitment_hasher.update(b"S");
                commitment_hasher.update(key.as_ref());
                commitment_hasher.update(utxo.amount.to_le_bytes());
            }

            for (idx, output) in tx.outputs.iter().enumerate() {
                let key = utxo_key(&tx.hash, idx as u32)?;
                let addr = output.address.clone();
                let utxo = crate::domain::utxo::utxo::Utxo::new(
                    addr.clone(), addr, output.amount,
                );
                let data = bincode::serialize(&utxo)
                    .map_err(|e| StorageError::Serialization(format!("output UTXO {}: {}", key, e)))?;
                ops.push(BatchWrite::Put { key: key.as_ref().to_vec(), value: data });
                let key_str = key.to_string();
                let addr_key = format!("addr:{}:{}", output.address, key_str);
                ops.push(BatchWrite::Put { key: addr_key.as_bytes().to_vec(), value: key.as_ref().to_vec() });

                undo.created_keys.push(key_str.clone());
                undo.created_addr_indexes.push((addr_key, key_str));

                // Stage for later txs in this block
                staged_outputs.insert(key, utxo);

                commitment_hasher.update(b"C");
                commitment_hasher.update(key.as_ref());
                commitment_hasher.update(output.address.as_bytes());
                commitment_hasher.update(output.amount.to_le_bytes());
            }

            // Mark tx as seen (uniqueness) + record for undo
            let seen_key = format!("tx_seen:{}", tx.hash);
            ops.push(BatchWrite::Put { key: seen_key.as_bytes().to_vec(), value: block_hash.as_bytes().to_vec() });
            undo.applied_tx_ids.push(tx.hash.clone());

            applied += 1;
            // Track fees from APPLIED txs only (not skipped/DUP).
            // Used for post-execution coinbase validation.
            applied_fees = applied_fees.saturating_add(tx.fee);
        }

        // Commitment + undo in same batch
        let commitment = format!("{:x}", commitment_hasher.finalize());
        let commit_key = format!("utxo:commitment:{}", block_hash);
        ops.push(BatchWrite::Put { key: commit_key.as_bytes().to_vec(), value: commitment.as_bytes().to_vec() });
        ops.push(BatchWrite::Put { key: prev_commitment_key.as_bytes().to_vec(), value: commitment.as_bytes().to_vec() });

        let undo_key = format!("utxo:undo:{}", block_hash);
        let undo_data = bincode::serialize(&undo)
            .map_err(|e| StorageError::Serialization(format!("undo data: {}", e)))?;
        ops.push(BatchWrite::Put { key: undo_key.as_bytes().to_vec(), value: undo_data });

        // ATOMIC COMMIT
        self.store.write_batch(ops).map_err(|e| StorageError::WriteFailed(format!("apply_block_dag atomic write: {}", e)))?;

        // Update cache
        for (key_str, _) in &undo.spent_utxos {
            // Parse "hexhash:index" string back to UtxoKey for cache lookup
            if let Some((hash, idx_s)) = key_str.rsplit_once(':') {
                if let Ok(idx) = idx_s.parse::<u32>() {
                    if let Ok(k) = utxo_key(hash, idx) {
                        if let Some(u) = self.cache.write().get_mut(&k) {
                            u.spent = true;
                        }
                    }
                }
            }
        }

        Ok((applied, skipped, applied_fees))
    }

    /// Rollback a block's UTXO changes using stored undo data.
    ///
    /// Reverses all changes made by apply_block_write_with_commitment:
    ///   - Restores spent UTXOs to unspent state
    ///   - Deletes created UTXOs
    ///   - Restores/deletes address indexes
    ///   - Removes undo data and commitment
    ///
    /// Used during DAG reorgs when the selected parent chain changes.
    pub fn rollback_block_undo(&self, block_hash: &str) -> Result<(), StorageError> {
        // Load undo data
        let undo_key = format!("utxo:undo:{}", block_hash);
        let raw = self.store.get_raw(undo_key.as_bytes())
            .ok_or_else(|| StorageError::KeyNotFound(format!("rollback: no undo data for block {}", block_hash)))?;
        let undo: BlockUndoData = bincode::deserialize(&raw)
            .map_err(|e| StorageError::Serialization(format!("rollback: deserialize undo: {}", e)))?;

        let mut ops: Vec<BatchWrite> = Vec::new();

        // 1. Restore spent UTXOs to their pre-spend state (unspent).
        //    CRITICAL: undo stores keys as Display strings "hexhash:index".
        //    We MUST reconstruct the canonical binary UtxoKey (36 bytes) to
        //    write at the same RocksDB key the UTXO was originally stored at.
        //    Using string.as_bytes() directly would produce ~70 UTF-8 bytes
        //    — a DIFFERENT key than the 36-byte binary original → data loss.
        for (key_str, original_utxo) in &undo.spent_utxos {
            // #27 — reject zero-amount UTXO restorations during rollback
            if original_utxo.amount == 0 {
                slog_warn!("utxo", "rejecting_zero_amount_restoration", key => key_str);
                continue;
            }
            // #28 — reject empty-address UTXO restorations during rollback
            if original_utxo.address.is_empty() {
                slog_warn!("utxo", "rejecting_empty_address_restoration", key => key_str);
                continue;
            }
            let data = bincode::serialize(original_utxo)
                .map_err(|e| StorageError::Serialization(format!("rollback: restored UTXO {}: {}", key_str, e)))?;
            if let Some((hash, idx_s)) = key_str.rsplit_once(':') {
                if let Ok(idx) = idx_s.parse::<u32>() {
                    let key = utxo_key(hash, idx)?;
                    ops.push(BatchWrite::Put { key: key.as_ref().to_vec(), value: data });
                }
            }
        }

        // 2. Delete UTXOs that were created by this block.
        //    Same pattern: reconstruct binary key from stored string.
        for key_str in &undo.created_keys {
            if let Some((hash, idx_s)) = key_str.rsplit_once(':') {
                if let Ok(idx) = idx_s.parse::<u32>() {
                    let key = utxo_key(hash, idx)?;
                    ops.push(BatchWrite::Delete { key: key.as_ref().to_vec() });
                }
            }
        }

        // 3. Restore address indexes that were deleted
        for (addr_key, utxo_key) in &undo.deleted_addr_indexes {
            ops.push(BatchWrite::Put { key: addr_key.as_bytes().to_vec(), value: utxo_key.as_bytes().to_vec() });
        }

        // 4. Delete address indexes that were created
        for (addr_key, _) in &undo.created_addr_indexes {
            ops.push(BatchWrite::Delete { key: addr_key.as_bytes().to_vec() });
        }

        // 5. Delete coinbase height metadata
        for meta_key in &undo.created_cb_heights {
            ops.push(BatchWrite::Delete { key: meta_key.as_bytes().to_vec() });
        }

        // 6. Remove tx_seen entries (allow re-application on new chain)
        for tx_id in &undo.applied_tx_ids {
            let seen_key = format!("tx_seen:{}", tx_id);
            ops.push(BatchWrite::Delete { key: seen_key.as_bytes().to_vec() });
        }

        // 7. Clean up undo data and commitment
        ops.push(BatchWrite::Delete { key: undo_key.as_bytes().to_vec() });
        let commit_key = format!("utxo:commitment:{}", block_hash);
        ops.push(BatchWrite::Delete { key: commit_key.as_bytes().to_vec() });

        // ATOMIC ROLLBACK — all or nothing
        self.store.write_batch(ops).map_err(|e| StorageError::WriteFailed(format!("rollback atomic write: {}", e)))?;

        // Invalidate cache entries
        let mut cache = self.cache.write();
        for (key_str, _) in &undo.spent_utxos {
            if let Some((hash, idx_s)) = key_str.rsplit_once(':') {
                if let Ok(idx) = idx_s.parse::<u32>() {
                    if let Ok(key) = utxo_key(hash, idx) {
                        cache.remove(&key);
                    }
                }
            }
        }
        for key_str in &undo.created_keys {
            if let Some((hash, idx_s)) = key_str.rsplit_once(':') {
                if let Ok(idx) = idx_s.parse::<u32>() {
                    if let Ok(key) = utxo_key(hash, idx) {
                        cache.remove(&key);
                    }
                }
            }
        }

        Ok(())
    }

    /// Prune undo data for finalized blocks. Once a block is finalized
    /// (deep enough below the tip), its undo data is no longer needed
    /// because no reorg can reach it. This saves significant disk space.
    ///
    /// Returns count of undo entries pruned.
    pub fn prune_finalized_undo_data(&self, finalized_block_hashes: &[String]) -> u64 {
        let mut ops: Vec<BatchWrite> = Vec::new();
        let mut count = 0u64;

        for block_hash in finalized_block_hashes {
            let undo_key = format!("utxo:undo:{}", block_hash);
            if self.store.get_raw(undo_key.as_bytes()).is_some() {
                ops.push(BatchWrite::Delete { key: undo_key.as_bytes().to_vec() });
                count += 1;
            }
        }

        if !ops.is_empty() {
            if let Err(e) = self.store.write_batch(ops) {
                slog_warn!("utxo", "prune_undo_data_failed", error => &e.to_string());
                return 0;
            }
        }

        count
    }

    /// Check if undo data exists for a block (i.e., it's NOT yet pruned/finalized).
    pub fn has_undo_data(&self, block_hash: &str) -> bool {
        let undo_key = format!("utxo:undo:{}", block_hash);
        self.store.get_raw(undo_key.as_bytes()).is_some()
    }

    /// Get stored UTXO commitment for a specific block.
    pub fn get_commitment(&self, block_hash: &str) -> Option<String> {
        let key = format!("utxo:commitment:{}", block_hash);
        self.store.get_raw(key.as_bytes())
            .and_then(|data| String::from_utf8(data).ok())
    }

    /// Backward-compatible wrapper: derives a deterministic block_hash from
    /// the first transaction's hash (coinbase). This ensures undo/commitment
    /// keys are always unique per block, never empty.
    pub fn apply_block_write(&self, transactions: &[Transaction], block_height: u64) -> Result<(), StorageError> {
        let block_hash = transactions.first()
            .map(|tx| tx.hash.as_str())
            .unwrap_or("unknown");
        self.apply_block_write_with_commitment(transactions, block_height, block_hash).map(|_| ())
    }

    /// DEPRECATED: Use rollback_block_undo(block_hash) instead.
    ///
    /// This legacy method attempts to reverse a block by inspecting current UTXO
    /// state, which can fail with intra-block dependencies or stale state.
    /// The undo-based rollback is deterministic and always correct.
    #[deprecated(note = "Use rollback_block_undo(block_hash) — undo-based rollback is consensus-safe")]
    pub fn rollback_block(&self, transactions: &[Transaction]) -> Result<(), StorageError> {
        let mut ops: Vec<BatchWrite> = Vec::new();

        // Stage cache mutations — DO NOT apply until DB write succeeds.
        // This prevents cache/DB desync if db.write() fails.
        let mut cache_removes: Vec<UtxoKey> = Vec::new();
        let mut cache_unspends: Vec<UtxoKey> = Vec::new();

        // Process transactions in REVERSE order
        for tx in transactions.iter().rev() {
            // 1) DELETE all outputs created by this transaction
            for (idx, _output) in tx.outputs.iter().enumerate() {
                let key = utxo_key(&tx.hash, idx as u32)?;

                ops.push(BatchWrite::Delete { key: key.as_ref().to_vec() });

                if let Some(utxo) = self.get_utxo(&key) {
                    let addr_key = format!("addr:{}:{}", utxo.address, key);
                    ops.push(BatchWrite::Delete { key: addr_key.as_bytes().to_vec() });
                }

                let mut meta = Vec::with_capacity(10 + 36);
                meta.extend_from_slice(b"cb_height:");
                meta.extend_from_slice(key.as_ref());
                ops.push(BatchWrite::Delete { key: meta });

                // Stage for cache (not applied yet)
                cache_removes.push(key);
            }

            // 2) RESTORE all inputs that were spent
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let key = utxo_key(&input.txid, input.index)?;

                    if let Some(mut utxo) = self.get_utxo(&key) {
                        // #27 — reject zero-amount UTXO restorations during rollback
                        if utxo.amount == 0 {
                            slog_warn!("utxo", "rejecting_zero_amount_restoration", key => &format!("{}:{}", input.txid, input.index));
                            continue;
                        }
                        // #28 — reject empty-address UTXO restorations during rollback
                        if utxo.address.is_empty() {
                            slog_warn!("utxo", "rejecting_empty_address_restoration", key => &format!("{}:{}", input.txid, input.index));
                            continue;
                        }
                        utxo.spent = false;
                        if let Ok(data) = bincode::serialize(&utxo) {
                            ops.push(BatchWrite::Put { key: key.as_ref().to_vec(), value: data });
                        }
                        let addr_key = format!("addr:{}:{}", utxo.address, key);
                        ops.push(BatchWrite::Put { key: addr_key.as_bytes().to_vec(), value: key.as_ref().to_vec() });

                        // Stage for cache (not applied yet)
                        cache_unspends.push(key);
                    }
                }
            }
        }

        // 3) DB commit FIRST — atomic, all or nothing
        self.store.write_batch(ops).map_err(|e| StorageError::WriteFailed(format!("rollback_block atomic write: {}", e)))?;

        // 4) ONLY after DB success: apply staged cache mutations.
        // If crash happens here, crash recovery will rebuild cache from DB.
        {
            let mut cache = self.cache.write();
            for key in &cache_removes {
                cache.remove(key);
            }
            for key in &cache_unspends {
                if let Some(cached) = cache.get_mut(key) {
                    cached.spent = false;
                }
            }
        }

        Ok(())
    }

    /// Compute a deterministic commitment hash over the entire UTXO set.
    /// Covers ALL fields: key, owner, amount, address, spent status.
    /// Used by crash recovery to detect ANY corruption, not just count mismatches.
    ///
    /// Algorithm: sort all UTXOs by key, hash each (key|owner|amount|address|spent),
    /// then hash all individual hashes together → single 64-char hex string.
    pub fn compute_commitment_hash(&self) -> String {
        use sha2::{Sha256, Digest};

        let mut all_utxos = self.export_all();
        all_utxos.sort_by(|a, b| a.0.cmp(&b.0));

        let mut master_hasher = Sha256::new();

        for (key, utxo) in &all_utxos {
            let mut entry_hasher = Sha256::new();
            entry_hasher.update(key.as_ref());
            entry_hasher.update(b"|");
            entry_hasher.update(utxo.owner.as_bytes());
            entry_hasher.update(b"|");
            entry_hasher.update(utxo.amount.to_le_bytes());
            entry_hasher.update(b"|");
            entry_hasher.update(utxo.address.as_bytes());
            entry_hasher.update(b"|");
            entry_hasher.update(if utxo.spent { b"1" as &[u8] } else { b"0" });

            let entry_hash = entry_hasher.finalize();
            master_hasher.update(entry_hash);
        }

        format!("{:x}", master_hasher.finalize())
    }

    // ── test helpers ────────────────────────────────────────────────────
    // Everything below until coinbase_created_height() is test-only.
    // Gated behind #[cfg(test)] so none of this compiles into production.

    /// Create an empty UtxoSet backed by a temporary DB.
    #[cfg(test)]
    pub fn try_new_empty() -> Result<Self, StorageError> {
        use std::collections::HashMap as HM;
        use crate::infrastructure::storage::rocksdb::utxo::utxo_store::UtxoStore;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("utxo_empty_{}", ts));
        let _ = std::fs::remove_dir_all(&path);
        let store = UtxoStore::new(path.to_str().unwrap_or("/tmp/utxo_empty"))?;
        Ok(Self {
            store: Arc::new(store) as Arc<dyn UtxoBackend>,
            cache: RwLock::new(HM::with_capacity(64)),
        })
    }

    /// Convenience wrapper that panics on failure — use only in tests.
    #[cfg(test)]
    pub fn new_empty() -> Self {
        Self::try_new_empty().expect("UtxoSet::new_empty failed")
    }

    #[cfg(test)]
    pub fn add_test_utxo(&mut self, key: &str, amount: u64, owner: &str) {
        // Parse "txhash:index" format for backward compatibility with tests
        let (hash, idx) = key.rsplit_once(':').expect("add_test_utxo key must be 'hash:index'");
        let index: u32 = idx.parse().expect("add_test_utxo index must be u32");
        let normalized = Self::normalize_test_hash(hash);
        let k = utxo_key(&normalized, index).expect("test hash should be valid");
        self.add_utxo(&k, owner.to_string(), amount, owner.to_string());
    }

    /// add_utxo by string key — convenience for tests.
    #[cfg(test)]
    pub fn add_utxo_str(&self, key: &str, owner: String, amount: u64, address: String) {
        self.add_utxo(&Self::parse_utxo_key(key), owner, amount, address);
    }

    /// add_utxo_coinbase by string key — convenience for tests.
    #[cfg(test)]
    pub fn add_utxo_coinbase_str(&self, key: &str, owner: String, amount: u64, address: String, created_height: u64) {
        self.add_utxo_coinbase(&Self::parse_utxo_key(key), owner, amount, address, created_height);
    }

    /// Parse a "hash:index" string into a UtxoKey.
    /// Convenience for tests and backward-compatible callers.
    ///
    /// If the hash portion isn't a valid 64-char hex string, it is
    /// auto-normalized via SHA-256 so that test code using short names
    /// like "tx1:0" still works deterministically.
    #[cfg(test)]
    pub fn parse_utxo_key(key_str: &str) -> UtxoKey {
        let (hash, idx) = key_str.rsplit_once(':').expect("utxo key must be 'hash:index'");
        let index: u32 = idx.parse().expect("utxo key index must be u32");
        let normalized = Self::normalize_test_hash(hash);
        utxo_key(&normalized, index).expect("test hash should be valid")
    }

    /// If `hash` is already a valid 64-char hex string, return it unchanged.
    /// Otherwise, SHA-256 hash it to produce a deterministic 64-char hex string.
    ///
    /// This exists ONLY for test convenience methods (`_str` helpers).
    /// Production code MUST call `utxo_key()` directly with validated hashes.
    #[cfg(test)]
    fn normalize_test_hash(hash: &str) -> String {
        let h = hash.trim();
        let h = if h.starts_with("0x") || h.starts_with("0X") { &h[2..] } else { h };
        // If already valid 64-char hex, pass through unchanged
        if h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')) {
            return h.to_string();
        }
        // Otherwise, SHA-256 the raw name to get a deterministic 64-char hex hash
        use sha2::{Sha256, Digest};
        hex::encode(Sha256::digest(hash.as_bytes()))
    }

    /// get_utxo by string key — convenience for tests.
    #[cfg(test)]
    pub fn get_utxo_str(&self, key: &str) -> Option<Utxo> {
        self.get_utxo(&Self::parse_utxo_key(key))
    }

    /// spend_utxo by string key — convenience for tests.
    #[cfg(test)]
    pub fn spend_utxo_str(&self, key: &str) {
        self.spend_utxo(&Self::parse_utxo_key(key));
    }

    /// spend_utxo_checked by string key — convenience for tests.
    #[cfg(test)]
    pub fn spend_utxo_checked_str(&self, key: &str, current_height: u64) -> Result<(), StorageError> {
        self.spend_utxo_checked(&Self::parse_utxo_key(key), current_height)
    }

    /// exists by string key — convenience for tests.
    #[cfg(test)]
    pub fn exists_str(&self, key: &str) -> bool {
        self.exists(&Self::parse_utxo_key(key))
    }

    /// exists_spendable by string key — convenience for tests.
    #[cfg(test)]
    pub fn exists_spendable_str(&self, key: &str, current_height: u64) -> bool {
        self.exists_spendable(&Self::parse_utxo_key(key), current_height)
    }

    /// coinbase_created_height by string key — convenience for tests.
    #[cfg(test)]
    pub fn coinbase_created_height_str(&self, key: &str) -> Option<u64> {
        self.coinbase_created_height(&Self::parse_utxo_key(key))
    }

    pub fn coinbase_created_height(&self, key: &UtxoKey) -> Option<u64> {
        let mut meta_key = Vec::with_capacity(10 + 36);
        meta_key.extend_from_slice(b"cb_height:");
        meta_key.extend_from_slice(key.as_ref());

        if let Some(v) = self.store.get_raw(&meta_key) {
            if v.len() >= 8 {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&v[..8]);
                return Some(u64::from_le_bytes(arr));
            }
        }
        None
    }
}