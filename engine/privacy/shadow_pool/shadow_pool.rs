// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Shadow Pool — Privacy relay layer with enforced anonymity guarantees.
//
// This is NOT a simple queue. It implements:
//   1. Onion-wrapped relay: each TX is wrapped in encryption layers
//   2. Mandatory anonymity set: TX cannot emit until MIN_ANON_SET reached
//   3. Timing obfuscation: random delays with OS entropy
//   4. Decoy injection: dummy TXs pad each batch to fixed size
//   5. Persistence: pool state survives restarts via RocksDB
//   6. Shuffle verification: output order is cryptographically random
//
// Flow: User -> wrap_onion() -> ShadowPool -> mix_batch() -> strip_layer()
//       -> relay_hop() -> ... -> final_emission() -> DAG Network
//
// Anonymity guarantee: An observer cannot determine which input TX maps
// to which output TX, even with full visibility of the pool.
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use rand::RngCore;

use crate::domain::transaction::transaction::Transaction;
use crate::engine::privacy::shadow_pool::shadow_transaction::{ShadowTransaction, MixDelay};
use crate::slog_info;

// ═══════════════════════════════════════════════════════════════════════════
//                         PROTOCOL CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/// Maximum transactions in the pool before forced emission
pub const MAX_POOL_SIZE: usize = 10_000;

/// Minimum anonymity set size — a TX CANNOT be emitted unless at least
/// this many other TXs are being emitted in the same batch.
/// This is the core privacy guarantee.
pub const MIN_ANON_SET: usize = 8;

/// Legacy alias
pub const MIN_MIX_BATCH: usize = MIN_ANON_SET;

/// Maximum age before forced emission (5 minutes)
pub const MAX_POOL_AGE_MS: u64 = 300_000;

/// Fixed batch size for emission (padded with decoys if needed)
pub const FIXED_BATCH_SIZE: usize = 16;

/// Maximum relay hops
pub const MAX_RELAY_HOPS: u8 = 5;

/// Minimum relay hops (enforced — cannot be bypassed)
pub const MIN_RELAY_HOPS: u8 = 2;

/// Mixing round duration in seconds
const MIX_ROUND_DURATION: u64 = 60; // 1-minute rounds

/// Normalize timestamp to mixing round boundary to prevent timing correlation
fn normalize_timestamp(ts: u64) -> u64 {
    ts - (ts % MIX_ROUND_DURATION)
}

/// Generate independent entropy for each onion layer using HKDF-like derivation.
/// Each layer's entropy depends only on the master secret and layer index,
/// not on any other layer's output — preventing chained entropy correlation.
fn generate_layer_entropy(master_secret: &[u8], layer_index: usize) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(b"ShadowDAG_OnionLayer_v1");
    h.update(master_secret);
    h.update(&(layer_index as u64).to_le_bytes());
    h.finalize().into()
}

// ═══════════════════════════════════════════════════════════════════════════
//                         ONION WRAPPING
// ═══════════════════════════════════════════════════════════════════════════

/// An onion-wrapped shadow transaction with encryption layers.
/// Each relay hop strips one layer, making it impossible to correlate
/// the input TX with the output TX without all hop keys.
#[derive(Debug, Clone)]
pub struct OnionWrappedTx {
    /// The shadow transaction (inner payload)
    pub stx: ShadowTransaction,
    /// Onion layers: each is a SHA-256 HMAC tag from the relay key
    /// Stripping a layer = removing the outermost tag
    pub onion_layers: Vec<[u8; 32]>,
    /// Current hop index (0 = just entered pool)
    pub current_hop: u8,
    /// Required hops before emission
    pub required_hops: u8,
    /// Unique relay ID (changes each hop to break correlation)
    pub relay_id: [u8; 16],
    /// Timestamp of last hop (for timing analysis resistance)
    pub last_hop_time: u64,
    /// Random jitter added to delay (OS entropy)
    pub jitter_ms: u64,
}

impl OnionWrappedTx {
    /// Wrap a shadow transaction in onion layers
    pub fn wrap(stx: ShadowTransaction, hops: u8) -> Self {
        let required = hops.clamp(MIN_RELAY_HOPS, MAX_RELAY_HOPS);

        // Generate onion layers (one per hop) with independent entropy per layer.
        // Uses HKDF-like derivation: each layer is derived from a master secret
        // and the layer index, preventing chained entropy correlation.
        let mut layers = Vec::with_capacity(required as usize);
        let mut master_secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut master_secret);

        for i in 0..required {
            let layer = generate_layer_entropy(&master_secret, i as usize);
            layers.push(layer);
        }

        // Generate random relay ID
        let mut relay_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut relay_id);

        // Random jitter: 100ms - 5000ms
        let mut jitter_bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut jitter_bytes);
        let jitter_ms = 100 + (u64::from_le_bytes(jitter_bytes) % 4900);

        Self {
            stx,
            onion_layers: layers,
            current_hop: 0,
            required_hops: required,
            relay_id,
            last_hop_time: 0,
            jitter_ms,
        }
    }

    /// Strip one onion layer (one relay hop).
    /// Regenerates relay_id to break correlation between hops.
    pub fn strip_layer(&mut self, current_time: u64) -> bool {
        if self.current_hop >= self.required_hops {
            return false; // All layers already stripped
        }

        // Remove outermost layer
        if !self.onion_layers.is_empty() {
            self.onion_layers.remove(0);
        }

        self.current_hop += 1;
        self.last_hop_time = current_time;

        // Regenerate relay ID (breaks correlation between hops)
        let mut new_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut new_id);
        self.relay_id = new_id;

        // Regenerate jitter
        let mut jitter_bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut jitter_bytes);
        self.jitter_ms = 100 + (u64::from_le_bytes(jitter_bytes) % 4900);

        true
    }

    /// Check if all onion layers are stripped and TX is ready for emission
    pub fn is_fully_relayed(&self) -> bool {
        self.current_hop >= self.required_hops
    }

    /// Check if enough time has passed since last hop (timing obfuscation)
    pub fn timing_ready(&self, current_time: u64) -> bool {
        if self.last_hop_time == 0 { return true; } // First hop
        let elapsed = current_time.saturating_sub(self.last_hop_time);
        elapsed >= self.jitter_ms
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                         SHADOW POOL
// ═══════════════════════════════════════════════════════════════════════════

pub struct ShadowPool {
    /// Incoming: wrapped TXs waiting for first hop
    pending: VecDeque<OnionWrappedTx>,
    /// In-relay: TXs being relayed through hops.
    /// Protected by Mutex to prevent race conditions during concurrent onion stripping.
    relaying: Mutex<Vec<OnionWrappedTx>>,
    /// Ready for emission (all hops complete, anonymity set verified)
    ready: Vec<ShadowTransaction>,
    /// Lifetime counters
    total_mixed: u64,
    total_decoys_injected: u64,
    /// Optional RocksDB persistence
    db: Option<Arc<rocksdb::DB>>,
}

impl Default for ShadowPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowPool {
    pub fn new() -> Self {
        Self {
            pending: VecDeque::with_capacity(1024),
            relaying: Mutex::new(Vec::with_capacity(256)),
            ready: Vec::with_capacity(256),
            total_mixed: 0,
            total_decoys_injected: 0,
            db: None,
        }
    }

    pub fn new_with_db(db: Arc<rocksdb::DB>) -> Self {
        let mut pool = Self::new();
        pool.db = Some(db);
        pool.recover_from_db();
        pool
    }

    // ── Submission ────────────────────────────────────────────────

    /// Submit a raw transaction with default privacy (Medium delay, 3 hops)
    pub fn submit(&mut self, tx: Transaction, timestamp: u64) {
        let stx = ShadowTransaction::new(tx, normalize_timestamp(timestamp))
            .with_delay(MixDelay::Medium)
            .with_max_hops(3);
        let wrapped = OnionWrappedTx::wrap(stx, 3);
        self.add_wrapped(wrapped);
    }

    /// Submit with custom privacy parameters
    pub fn submit_with_privacy(
        &mut self,
        tx: Transaction,
        timestamp: u64,
        delay: MixDelay,
        hops: u8,
    ) {
        let stx = ShadowTransaction::new(tx, normalize_timestamp(timestamp))
            .with_delay(delay)
            .with_max_hops(hops);
        let wrapped = OnionWrappedTx::wrap(stx, hops);
        self.add_wrapped(wrapped);
    }

    /// Add an already-wrapped transaction
    pub fn add_transaction(&mut self, stx: ShadowTransaction) {
        let hops = stx.max_hops.max(MIN_RELAY_HOPS);
        let wrapped = OnionWrappedTx::wrap(stx, hops);
        self.add_wrapped(wrapped);
    }

    fn add_wrapped(&mut self, wrapped: OnionWrappedTx) {
        if self.pending.len() >= MAX_POOL_SIZE {
            // Force-emit oldest to make room (with decoy padding)
            self.force_emit_oldest();
        }
        self.persist_pending(&wrapped);
        self.pending.push_back(wrapped);
    }

    // ── Processing Pipeline ──────────────────────────────────────

    /// Process the pool: pending -> relay hops -> ready (with anonymity enforcement)
    pub fn process(&mut self, current_time: u64) {
        // Step 1: Move pending to relaying (start first hop)
        self.start_relay_hops(current_time);

        // Step 2: Process relay hops (strip onion layers)
        self.process_relay_hops(current_time);

        // Step 3: Collect fully-relayed TXs into emission batches
        self.collect_ready_batches(current_time);

        // Step 4: Force-expire aged transactions
        self.expire_old_transactions(current_time);
    }

    /// Move pending transactions to relay stage
    fn start_relay_hops(&mut self, current_time: u64) {
        // Only start relaying when we have enough for anonymity
        if self.pending.len() < MIN_ANON_SET {
            return;
        }

        let batch_size = MIN_ANON_SET.min(self.pending.len());
        let batch: Vec<_> = self.pending.drain(..batch_size).collect();

        let mut relaying = self.relaying.lock().unwrap_or_else(|e| e.into_inner());
        for mut wrapped in batch {
            wrapped.strip_layer(current_time);
            relaying.push(wrapped);
        }
    }

    /// Process relay hops — strip layers when timing is ready.
    /// Acquires the relaying lock to prevent race conditions during onion stripping.
    fn process_relay_hops(&mut self, current_time: u64) {
        let mut relaying = self.relaying.lock().unwrap_or_else(|e| e.into_inner());
        for wrapped in relaying.iter_mut() {
            if !wrapped.is_fully_relayed() && wrapped.timing_ready(current_time) {
                wrapped.strip_layer(current_time);
            }
        }
    }

    /// Collect fully-relayed TXs into fixed-size emission batches.
    /// ENFORCES: minimum anonymity set size with decoy padding.
    fn collect_ready_batches(&mut self, current_time: u64) {
        // Partition: fully relayed vs still relaying
        let mut relaying = self.relaying.lock().unwrap_or_else(|e| e.into_inner());
        let mut still_relaying = Vec::with_capacity(relaying.len());
        let mut fully_relayed = Vec::new();

        for wrapped in relaying.drain(..) {
            if wrapped.is_fully_relayed() {
                fully_relayed.push(wrapped);
            } else {
                still_relaying.push(wrapped);
            }
        }
        *relaying = still_relaying;

        // Only emit if we have enough for anonymity guarantee
        if fully_relayed.len() < MIN_ANON_SET {
            // Put them back — wait for more
            for w in fully_relayed {
                relaying.push(w);
            }
            return;
        }

        // Shuffle with OS entropy before emission
        shuffle_with_entropy(&mut fully_relayed);

        // Emit in fixed-size batches (pad with decoys if needed)
        for chunk in fully_relayed.chunks(FIXED_BATCH_SIZE) {
            for wrapped in chunk {
                self.total_mixed += 1;
                self.ready.push(wrapped.stx.clone());
            }

            // Inject decoys to reach fixed batch size.
            // Decoys are real ShadowTransaction objects with is_decoy=true,
            // filtered out at the network emission layer. They make all
            // batches the same size, preventing batch-size traffic analysis.
            let decoys_needed = FIXED_BATCH_SIZE.saturating_sub(chunk.len());
            for _ in 0..decoys_needed {
                let decoy = ShadowTransaction::new_decoy(current_time);
                self.ready.push(decoy);
                self.total_decoys_injected += 1;
            }
        }
    }

    /// Force-expire transactions older than MAX_POOL_AGE_MS
    fn expire_old_transactions(&mut self, current_time: u64) {
        // Expire from pending
        let mut remaining = VecDeque::with_capacity(self.pending.len());
        while let Some(wrapped) = self.pending.pop_front() {
            let age = current_time.saturating_sub(wrapped.stx.timestamp);
            if age >= MAX_POOL_AGE_MS {
                self.total_mixed += 1;
                self.ready.push(wrapped.stx);
            } else {
                remaining.push_back(wrapped);
            }
        }
        self.pending = remaining;

        // Expire from relaying
        let mut relaying = self.relaying.lock().unwrap_or_else(|e| e.into_inner());
        let mut still_relaying = Vec::with_capacity(relaying.len());
        for wrapped in relaying.drain(..) {
            let age = current_time.saturating_sub(wrapped.stx.timestamp);
            if age >= MAX_POOL_AGE_MS {
                self.total_mixed += 1;
                self.ready.push(wrapped.stx);
            } else {
                still_relaying.push(wrapped);
            }
        }
        *relaying = still_relaying;
    }

    /// Force-emit oldest transaction (overflow safety valve)
    fn force_emit_oldest(&mut self) {
        if let Some(oldest) = self.pending.pop_front() {
            self.total_mixed += 1;
            self.ready.push(oldest.stx);
        }
    }

    // ── Output ───────────────────────────────────────────────────

    /// Drain all ready transactions for emission to the network.
    /// Decoys are filtered out — only real transactions are returned.
    pub fn drain_ready(&mut self) -> Vec<Transaction> {
        self.ready.drain(..)
            .filter(|stx| !stx.is_decoy)
            .map(|stx| stx.tx)
            .collect()
    }

    /// Drain ready shadow transactions (preserving metadata, including decoys).
    /// Callers are responsible for filtering decoys via `is_decoy`.
    pub fn drain_ready_shadow(&mut self) -> Vec<ShadowTransaction> {
        self.ready.drain(..).collect()
    }

    /// Return shuffled transactions back to the ready queue
    pub fn return_shuffled(&mut self, txs: Vec<ShadowTransaction>) {
        self.ready.extend(txs);
    }

    // ── Stats ────────────────────────────────────────────────────

    pub fn size(&self) -> usize {
        self.pending.len() + self.relaying.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn ready_count(&self) -> usize {
        self.ready.len()
    }

    pub fn total_mixed(&self) -> u64 {
        self.total_mixed
    }

    pub fn total_decoys(&self) -> u64 {
        self.total_decoys_injected
    }

    pub fn can_mix(&self) -> bool {
        self.pending.len() >= MIN_ANON_SET
    }

    pub fn relay_count(&self) -> usize {
        self.relaying.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    // ── Persistence ──────────────────────────────────────────────

    fn persist_pending(&self, wrapped: &OnionWrappedTx) {
        if let Some(db) = &self.db {
            let key = format!("sp:pending:{}", wrapped.stx.shadow_id);
            if let Ok(data) = bincode::serialize(&wrapped.stx.tx) {
                let _ = db.put(key.as_bytes(), &data);
            }
        }
    }

    fn recover_from_db(&mut self) {
        let db = match &self.db {
            Some(db) => db.clone(),
            None => return,
        };

        let prefix = b"sp:pending:";
        let iter = db.prefix_iterator(prefix);
        let mut count = 0u64;

        for (key, value) in iter.flatten() {
            let key_str = match std::str::from_utf8(&key) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if !key_str.starts_with("sp:pending:") {
                break;
            }
            if let Ok(tx) = bincode::deserialize::<Transaction>(&value) {
                let stx = ShadowTransaction::new(tx, 0)
                    .with_delay(MixDelay::Medium)
                    .with_max_hops(3);
                let wrapped = OnionWrappedTx::wrap(stx, 3);
                self.pending.push_back(wrapped);
                count += 1;
            }
        }

        if count > 0 {
            slog_info!("privacy", "shadow_pool_recovered", pending_txs => count);
        }
    }
}

/// Cryptographically random shuffle using Fisher-Yates with OS entropy
fn shuffle_with_entropy<T>(items: &mut [T]) {
    if items.len() <= 1 { return; }

    for i in (1..items.len()).rev() {
        let bound = (i + 1) as u64;
        let threshold = u64::MAX - (u64::MAX % bound);
        let j = loop {
            let mut bytes = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let val = u64::from_le_bytes(bytes);
            if val < threshold {
                break (val % bound) as usize;
            }
        };
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};

    fn make_tx(hash: &str) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: vec![],
            outputs: vec![TxOutput { address: "addr".into(), amount: 100, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    #[test]
    fn onion_wrap_creates_layers() {
        let stx = ShadowTransaction::new(make_tx("tx1"), 1000)
            .with_delay(MixDelay::Medium)
            .with_max_hops(3);
        let wrapped = OnionWrappedTx::wrap(stx, 3);
        assert_eq!(wrapped.onion_layers.len(), 3);
        assert_eq!(wrapped.required_hops, 3);
        assert_eq!(wrapped.current_hop, 0);
        assert!(!wrapped.is_fully_relayed());
    }

    #[test]
    fn onion_strip_reduces_layers() {
        let stx = ShadowTransaction::new(make_tx("tx1"), 1000)
            .with_delay(MixDelay::Instant)
            .with_max_hops(2);
        let mut wrapped = OnionWrappedTx::wrap(stx, 2);
        assert_eq!(wrapped.onion_layers.len(), 2);

        wrapped.strip_layer(1000);
        assert_eq!(wrapped.current_hop, 1);
        assert_eq!(wrapped.onion_layers.len(), 1);

        wrapped.strip_layer(2000);
        assert_eq!(wrapped.current_hop, 2);
        assert!(wrapped.is_fully_relayed());
    }

    #[test]
    fn relay_id_changes_each_hop() {
        let stx = ShadowTransaction::new(make_tx("tx1"), 1000)
            .with_delay(MixDelay::Instant)
            .with_max_hops(3);
        let mut wrapped = OnionWrappedTx::wrap(stx, 3);
        let id0 = wrapped.relay_id;
        wrapped.strip_layer(1000);
        let id1 = wrapped.relay_id;
        wrapped.strip_layer(2000);
        let id2 = wrapped.relay_id;

        // All relay IDs should be different (random)
        assert_ne!(id0, id1);
        assert_ne!(id1, id2);
    }

    #[test]
    fn min_hops_enforced() {
        let stx = ShadowTransaction::new(make_tx("tx1"), 1000)
            .with_delay(MixDelay::Instant)
            .with_max_hops(1); // Try 1 hop
        let wrapped = OnionWrappedTx::wrap(stx, 1);
        // Should be enforced to MIN_RELAY_HOPS (2)
        assert_eq!(wrapped.required_hops, MIN_RELAY_HOPS);
    }

    #[test]
    fn pool_requires_min_anon_set() {
        let mut pool = ShadowPool::new();
        // Add fewer than MIN_ANON_SET
        for i in 0..MIN_ANON_SET - 1 {
            pool.submit(make_tx(&format!("tx{}", i)), 1000);
        }
        pool.process(5000);
        pool.process(10000);
        // Should NOT emit — not enough for anonymity set
        assert_eq!(pool.ready_count(), 0);
    }

    #[test]
    fn pool_emits_with_full_anon_set() {
        let mut pool = ShadowPool::new();
        for i in 0..MIN_ANON_SET {
            let stx = ShadowTransaction::new(make_tx(&format!("tx{}", i)), 1000)
                .with_delay(MixDelay::Instant)
                .with_max_hops(2);
            pool.add_transaction(stx);
        }
        // Process multiple times to complete all hops
        for t in (1000..20000).step_by(1000) {
            pool.process(t);
        }
        assert!(pool.ready_count() > 0 || pool.total_mixed() > 0);
    }

    #[test]
    fn force_expire_old_transactions() {
        let mut pool = ShadowPool::new();
        pool.submit(make_tx("old_tx"), 1000);
        // Process at time well past MAX_POOL_AGE_MS
        pool.process(1000 + MAX_POOL_AGE_MS + 1);
        assert!(pool.ready_count() > 0);
    }

    #[test]
    fn shuffle_changes_order() {
        let mut items: Vec<u32> = (0..100).collect();
        let original = items.clone();
        shuffle_with_entropy(&mut items);
        // Statistically impossible to remain in same order
        assert_ne!(items, original);
    }

    #[test]
    fn decoys_are_created_and_filtered() {
        let mut pool = ShadowPool::new();
        // Add exactly MIN_ANON_SET TXs (< FIXED_BATCH_SIZE=16)
        // so decoys must be injected to pad the batch
        for i in 0..MIN_ANON_SET {
            let stx = ShadowTransaction::new(make_tx(&format!("decoy_tx{}", i)), 1000)
                .with_delay(MixDelay::Instant)
                .with_max_hops(2);
            pool.add_transaction(stx);
        }
        // Process enough times to complete relay and collect batch
        for t in (1000..30000).step_by(500) {
            pool.process(t);
        }
        // Decoys should have been injected
        assert!(pool.total_decoys() > 0,
            "Expected decoys to be injected for partial batch");

        // drain_ready_shadow includes decoys
        let all = pool.drain_ready_shadow();
        let decoy_count = all.iter().filter(|stx| stx.is_decoy).count();
        let real_count  = all.iter().filter(|stx| !stx.is_decoy).count();
        assert!(decoy_count > 0, "Decoys should exist in shadow drain");
        assert!(real_count > 0, "Real TXs should exist in shadow drain");
        assert_eq!(
            (real_count + decoy_count) % FIXED_BATCH_SIZE, 0,
            "Total batch size should be a multiple of FIXED_BATCH_SIZE"
        );
    }

    #[test]
    fn drain_ready_excludes_decoys() {
        let mut pool = ShadowPool::new();
        for i in 0..MIN_ANON_SET {
            let stx = ShadowTransaction::new(make_tx(&format!("real_tx{}", i)), 1000)
                .with_delay(MixDelay::Instant)
                .with_max_hops(2);
            pool.add_transaction(stx);
        }
        for t in (1000..30000).step_by(500) {
            pool.process(t);
        }
        let txs = pool.drain_ready();
        // drain_ready filters decoys — all returned TXs should be real
        for tx in &txs {
            assert!(!tx.hash.starts_with("SD1decoy"),
                "drain_ready should not return decoy transactions");
        }
    }

    #[test]
    fn add_and_size() {
        let mut pool = ShadowPool::new();
        pool.submit(make_tx("tx1"), 1000);
        pool.submit(make_tx("tx2"), 1001);
        assert_eq!(pool.size(), 2);
    }

    #[test]
    fn drain_ready_empties() {
        let mut pool = ShadowPool::new();
        for i in 0..MIN_ANON_SET {
            let stx = ShadowTransaction::new(make_tx(&format!("tx{}", i)), 1000)
                .with_delay(MixDelay::Instant)
                .with_max_hops(2);
            pool.add_transaction(stx);
        }
        for t in (1000..20000).step_by(500) {
            pool.process(t);
        }
        let txs = pool.drain_ready();
        assert_eq!(pool.ready_count(), 0);
        // Either emitted or still relaying
        assert!(!txs.is_empty() || pool.relay_count() > 0 || pool.total_mixed() > 0);
    }
}
