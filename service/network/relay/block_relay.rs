// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::NetworkError;
use crate::domain::block::block::Block;
use crate::{slog_error, slog_warn};
use crate::service::network::p2p::p2p::{P2PMessage, push_outbound};
use crate::service::network::p2p::peer_manager::PeerManager;
use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;

pub const MAX_ORPHANS: usize = 1_024;

pub const ORPHAN_TTL_SECS: u64 = 3_600;

/// Maximum serialized size of a single orphan entry (4 MB).
/// Entries exceeding this are skipped during deserialization to prevent
/// memory exhaustion from maliciously large or corrupted DB values.
pub const MAX_ORPHAN_ENTRY_SIZE: usize = 4 * 1024 * 1024;

const PFX_ORPHAN: &[u8] = b"orphan:block:";

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
struct OrphanEntry {
    block:       Block,
    received_at: u64,
}

pub struct BlockRelay {
    db:           DB,
    _peer_manager: Arc<PeerManager>,
    block_store:  Option<Arc<BlockStore>>,
}

impl BlockRelay {
    pub fn new(path: &str, peer_manager: Arc<PeerManager>) -> Result<Self, NetworkError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, Path::new(path))
            .map_err(|e| NetworkError::Storage(crate::errors::StorageError::OpenFailed {
                path: path.to_string(),
                reason: e.to_string(),
            }))?;
        Ok(Self { db, _peer_manager: peer_manager, block_store: None })
    }

    pub fn with_block_store(mut self, store: Arc<BlockStore>) -> Self {
        self.block_store = Some(store);
        self
    }

    /// Check if a block hash is known — either in the relay cache or
    /// in the authoritative block store. The relay DB is checked first
    /// as a fast path for recently relayed blocks.
    fn is_block_known(&self, hash: &str) -> bool {
        let relay_key = format!("relay:block:{}", hash);
        if matches!(self.db.get(relay_key.as_bytes()), Ok(Some(_))) {
            return true;
        }
        if let Some(store) = &self.block_store {
            return store.block_exists(hash);
        }
        false
    }

    pub fn broadcast_block(&self, block: &Block) {
        let key = format!("relay:block:{}", block.header.hash);

        // Skip if already relayed
        if matches!(self.db.get(key.as_bytes()), Ok(Some(_))) {
            return;
        }

        // Serialize block as bincode for the P2PMessage::Block payload
        let block_bytes = match bincode::serialize(block) {
            Ok(d) => d,
            Err(e) => {
                slog_error!("relay", "block_serialize_error", error => e);
                return;
            }
        };

        // Push to the global outbound queue — each peer connection thread
        // will drain this queue and send via its TCP stream.
        push_outbound(P2PMessage::Block { data: block_bytes });

        // Mark AFTER successful queue push
        if let Err(e) = self.db.put(key.as_bytes(), b"1") {
            slog_error!("relay", "block_relay_db_put_error", error => e);
        }

        log::debug!(
            "[BlockRelay] Queued block {} (height {}) for broadcast",
            &block.header.hash[..8], block.header.height
        );
    }

    pub fn receive_block(&self, block: Block) -> bool {
        let key = format!("relay:block:{}", block.header.hash);

        if matches!(self.db.get(key.as_bytes()), Ok(Some(_))) {
            return false;
        }

        if let Err(e) = self.db.put(key.as_bytes(), b"1") {
            slog_warn!("relay", "receive_block_put_error", hash => &block.header.hash, error => e);
        }

        if block.header.height == 0 || block.header.parents.is_empty() {
            if let Ok(block_bytes) = bincode::serialize(&block) {
                push_outbound(P2PMessage::Block { data: block_bytes });
            }
            return true;
        }

        let all_parents_known = block.header.parents.iter().all(|p| {
            self.is_block_known(p)
        });

        if all_parents_known {
            // Relay to other peers (gossip propagation).
            // Already marked as seen above, so push directly to outbound queue.
            if let Ok(block_bytes) = bincode::serialize(&block) {
                push_outbound(P2PMessage::Block { data: block_bytes });
            }
            true
        } else {
            self.add_to_orphan_pool(block);
            false
        }
    }

    pub fn add_to_orphan_pool(&self, block: Block) {
        self.prune_orphans();

        if self.orphan_count() >= MAX_ORPHANS {
            self.evict_oldest_orphan();
        }

        let entry = OrphanEntry {
            block,
            received_at: Self::now(),
        };

        if let Ok(data) = bincode::serialize(&entry) {
            // Enforce size limit at WRITE time (not just read time)
            if data.len() > MAX_ORPHAN_ENTRY_SIZE {
                slog_warn!("relay", "orphan_entry_too_large",
                    size => data.len(), max => MAX_ORPHAN_ENTRY_SIZE);
                return;
            }
            let key = format!("orphan:block:{}", entry.block.header.hash);
            if let Err(e) = self.db.put(key.as_bytes(), &data) {
                slog_warn!("relay", "orphan_pool_put_error", hash => &entry.block.header.hash, error => e);
            }
        }
    }

    pub fn process_orphans(&self, parent_hash: &str) -> Vec<Block> {
        self.resolve_orphans(parent_hash)
    }

    pub fn resolve_orphans(&self, parent_hash: &str) -> Vec<Block> {
        self.prune_orphans();

        let mut resolved = Vec::new();
        let mut queue = vec![parent_hash.to_string()];
        // Track blocks resolved in this call so cascading resolution works
        // without writing premature "known" markers to the DB. The caller
        // is responsible for marking blocks as known AFTER validation via
        // mark_block_known().
        let mut resolved_hashes = std::collections::HashSet::<String>::new();

        // Iterative BFS: each resolved block may unlock further orphans
        // whose other parents were already known.
        while let Some(current_parent) = queue.pop() {
            let all_orphans: Vec<OrphanEntry> = self.db
                .prefix_iterator(PFX_ORPHAN)
                .filter_map(|r| match r {
                    Ok(kv) => Some(kv),
                    Err(e) => {
                        slog_warn!("relay", "orphan_iter_read_error", error => e);
                        None
                    }
                })
                .filter(|(_, v)| v.len() <= MAX_ORPHAN_ENTRY_SIZE)
                .filter_map(|(_, v)| bincode::deserialize::<OrphanEntry>(&v).ok())
                .collect();

            for entry in all_orphans {
                if !entry.block.header.parents.iter().any(|p| p == &current_parent) {
                    continue;
                }

                let all_known = entry.block.header.parents.iter().all(|p| {
                    resolved_hashes.contains(p) || self.is_block_known(p)
                });

                if all_known {
                    let orphan_key = format!("orphan:block:{}", entry.block.header.hash);
                    if let Err(e) = self.db.delete(orphan_key.as_bytes()) {
                        slog_warn!("relay", "orphan_delete_error", hash => &entry.block.header.hash, error => e);
                    }

                    // Do NOT write relay:block:{hash}=1 here — the block has
                    // not been validated yet. The caller must call
                    // mark_block_known() after successful validation.

                    // Track locally for cascading BFS
                    resolved_hashes.insert(entry.block.header.hash.clone());

                    // Enqueue so orphans waiting on THIS block get checked next
                    queue.push(entry.block.header.hash.clone());
                    resolved.push(entry.block);
                }
            }
        }

        resolved
    }

    /// Mark a block as known in the relay DB. Callers should invoke this
    /// AFTER the block has been fully validated, not before.
    pub fn mark_block_known(&self, hash: &str) {
        let relay_key = format!("relay:block:{}", hash);
        if let Err(e) = self.db.put(relay_key.as_bytes(), b"1") {
            slog_error!("relay", "mark_block_known_error", hash => hash, error => e);
        }
    }

    pub fn is_orphan(&self, hash: &str) -> bool {
        let key = format!("orphan:block:{}", hash);
        matches!(self.db.get(key.as_bytes()), Ok(Some(_)))
    }

    pub fn orphan_count(&self) -> usize {
        self.db
            .prefix_iterator(PFX_ORPHAN)
            .filter_map(|r| match r {
                Ok(kv) => Some(kv),
                Err(e) => {
                    slog_warn!("relay", "orphan_count_iter_error", error => e);
                    None
                }
            })
            .count()
    }

    pub fn prune_orphans(&self) {
        let cutoff = Self::now().saturating_sub(ORPHAN_TTL_SECS);

        let stale_keys: Vec<Vec<u8>> = self.db
            .prefix_iterator(PFX_ORPHAN)
            .filter_map(|r| match r {
                Ok(kv) => Some(kv),
                Err(e) => {
                    slog_warn!("relay", "prune_orphans_iter_error", error => e);
                    None
                }
            })
            .filter(|(_, v)| {
                bincode::deserialize::<OrphanEntry>(v)
                    .map(|e| e.received_at < cutoff)
                    .unwrap_or(false)
            })
            .map(|(k, _)| k.to_vec())
            .collect();

        let pruned = stale_keys.len();
        for k in &stale_keys {
            if let Err(e) = self.db.delete(k) {
                slog_warn!("relay", "prune_orphan_delete_error", error => e);
            }
        }

        if pruned > 0 {
            log::debug!("[BlockRelay] Pruned {} stale orphans", pruned);
        }
    }

    pub fn clear_orphan_pool(&self) {
        let keys: Vec<Vec<u8>> = self.db
            .prefix_iterator(PFX_ORPHAN)
            .filter_map(|r| match r {
                Ok(kv) => Some(kv),
                Err(e) => {
                    slog_warn!("relay", "clear_orphan_pool_iter_error", error => e);
                    None
                }
            })
            .map(|(k, _)| k.to_vec())
            .collect();
        for k in &keys {
            if let Err(e) = self.db.delete(k) {
                slog_warn!("relay", "clear_orphan_pool_delete_error", error => e);
            }
        }
    }

    fn evict_oldest_orphan(&self) {
        let oldest: Option<(u64, Vec<u8>)> = self.db
            .prefix_iterator(PFX_ORPHAN)
            .filter_map(|r| match r {
                Ok(kv) => Some(kv),
                Err(e) => {
                    slog_warn!("relay", "evict_oldest_orphan_iter_error", error => e);
                    None
                }
            })
            .filter_map(|(k, v)| {
                bincode::deserialize::<OrphanEntry>(&v)
                    .ok()
                    .map(|e| (e.received_at, k.to_vec()))
            })
            .min_by_key(|(ts, _)| *ts);

        if let Some((_, k)) = oldest {
            if let Err(e) = self.db.delete(&k) {
                slog_warn!("relay", "evict_oldest_orphan_delete_error", error => e);
            }
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::domain::block::block::Block;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::block::block_body::BlockBody;
    use crate::service::network::p2p::peer_manager::PeerManager;

    fn make_relay() -> BlockRelay {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = format!("/tmp/test_relay_v8_{}_{}", std::process::id(), id);
        let pm = Arc::new(PeerManager::new_temp());
        BlockRelay::new(&path, pm).expect("BlockRelay::new failed")
    }

    fn make_block(hash: &str, parents: Vec<&str>, height: u64) -> Block {
        Block {
            header: BlockHeader {
                version:     1,
                hash:        hash.to_string(),
                parents:     parents.into_iter().map(|s| s.to_string()).collect(),
                merkle_root: "root".to_string(),
                timestamp:   1_735_689_600,
                nonce:       0,
                difficulty:  1,
                height,
                blue_score:      0,
                selected_parent: None,
                utxo_commitment: None,
                extra_nonce: 0,
            },
            body: BlockBody { transactions: vec![] },
        }
    }

    #[test]
    fn orphan_queued_when_parent_missing() {
        let relay = make_relay();
        relay.clear_orphan_pool();

        let orphan = make_block("child_hash", vec!["unknown_parent"], 1);
        let result = relay.receive_block(orphan);
        assert!(!result, "Block with unknown parent must go to orphan pool");
        assert!(relay.is_orphan("child_hash"), "Block must be in orphan pool");
    }

    #[test]
    fn orphan_resolved_when_parent_arrives() {
        let relay = make_relay();
        relay.clear_orphan_pool();

        let parent_key = "relay:block:parent_a";
        let _ = relay.db.put(parent_key.as_bytes(), b"1");

        let orphan = make_block("orphan_b", vec!["parent_a"], 1);
        relay.add_to_orphan_pool(orphan);

        let resolved = relay.resolve_orphans("parent_a");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].header.hash, "orphan_b");
        assert!(!relay.is_orphan("orphan_b"), "Resolved block must be removed from pool");
    }

    #[test]
    fn cascading_orphan_resolution() {
        let relay = make_relay();
        relay.clear_orphan_pool();

        // Mark root parent as known
        let _ = relay.db.put(b"relay:block:root", b"1");

        // child_a depends on root (known)
        // child_b depends on child_a (orphan until child_a resolves)
        let child_a = make_block("child_a", vec!["root"], 1);
        let child_b = make_block("child_b", vec!["child_a"], 2);
        relay.add_to_orphan_pool(child_a);
        relay.add_to_orphan_pool(child_b);

        let resolved = relay.resolve_orphans("root");
        let hashes: Vec<&str> = resolved.iter().map(|b| b.header.hash.as_str()).collect();
        assert!(hashes.contains(&"child_a"), "child_a should resolve (parent root is known)");
        assert!(hashes.contains(&"child_b"), "child_b should cascade-resolve (child_a now known)");
        assert!(!relay.is_orphan("child_a"));
        assert!(!relay.is_orphan("child_b"));
    }

    #[test]
    fn partial_parents_stay_orphaned() {
        let relay = make_relay();
        relay.clear_orphan_pool();

        // Mark only parent_x as known; parent_y is missing
        let _ = relay.db.put(b"relay:block:parent_x", b"1");

        // Block requires both parents
        let block = make_block("needs_both", vec!["parent_x", "parent_y"], 1);
        relay.add_to_orphan_pool(block);

        let resolved = relay.resolve_orphans("parent_x");
        assert!(resolved.is_empty(), "Block with a missing parent must stay orphaned");
        assert!(relay.is_orphan("needs_both"));
    }

    #[test]
    fn genesis_always_accepted() {
        let relay = make_relay();
        let genesis = make_block("genesis_hash", vec![], 0);
        assert!(relay.receive_block(genesis), "Genesis must be accepted immediately");
    }

    #[test]
    fn orphan_count_bounded() {
        let relay = make_relay();
        let _count = relay.orphan_count();
    }
}
