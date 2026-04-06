// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Key Images — Deterministic identifiers that prevent double-spending
// in ring signature transactions without revealing the signer.
//
// Each private key can only produce ONE key image. If the same key image
// appears twice, the second transaction is a double-spend attempt.
//
// I = H(private_key || domain_tag) mapped to a curve point
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use std::collections::HashSet;

/// Key image store for double-spend detection.
/// Uses RocksDB for persistence — survives node restarts.
/// Also has in-memory cache for fast lookups.
pub struct KeyImageStore {
    cache: HashSet<String>,
    db:    Option<rocksdb::DB>,
}

impl Default for KeyImageStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyImageStore {
    pub fn new() -> Self {
        Self { cache: HashSet::new(), db: None }
    }

    /// Maximum key images in memory cache (rest are in RocksDB)
    const MAX_CACHE: usize = 500_000;

    /// Create with RocksDB persistence
    pub fn with_db(path: &str) -> Self {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, path).ok();
        // Load recent key images into cache (capped at MAX_CACHE)
        let mut cache = HashSet::new();
        if let Some(ref db) = db {
            let iter = db.prefix_iterator(b"ki:");
            for item in iter {
                if cache.len() >= Self::MAX_CACHE { break; } // Cap cache loading
                if let Ok((k, _)) = item {
                    let k_str = String::from_utf8_lossy(&k);
                    if !k_str.starts_with("ki:") { break; }
                    cache.insert(k_str[3..].to_string());
                }
            }
        }
        Self { cache, db }
    }

    /// Check if a key image has been seen (double-spend attempt)
    pub fn is_spent(&self, key_image: &str) -> bool {
        if self.cache.contains(key_image) { return true; }
        // Fallback to DB if not in cache
        if let Some(ref db) = self.db {
            let key = format!("ki:{}", key_image);
            return db.get(key.as_bytes()).unwrap_or(None).is_some();
        }
        false
    }

    /// Record a key image as spent (persists to DB, cache capped)
    pub fn mark_spent(&mut self, key_image: &str) -> bool {
        // Evict from cache if too large (DB remains authoritative)
        if self.cache.len() >= Self::MAX_CACHE {
            // Remove ~10% oldest entries
            let to_remove: Vec<String> = self.cache.iter().take(Self::MAX_CACHE / 10).cloned().collect();
            for k in to_remove { self.cache.remove(&k); }
        }
        let is_new = self.cache.insert(key_image.to_string());
        if is_new {
            if let Some(ref db) = self.db {
                let key = format!("ki:{}", key_image);
                let _ = db.put(key.as_bytes(), b"1");
            }
        }
        is_new
    }

    /// Batch check: returns the first duplicate if any
    pub fn find_duplicate(&self, images: &[String]) -> Option<String> {
        for img in images {
            if self.is_spent(img) {
                return Some(img.clone());
            }
        }
        let mut batch_set = HashSet::new();
        for img in images {
            if !batch_set.insert(img) {
                return Some(img.clone());
            }
        }
        None
    }

    pub fn count(&self) -> usize { self.cache.len() }

    /// Compact the underlying RocksDB to reclaim disk space.
    /// Should be called periodically (e.g., weekly) for long-running nodes.
    pub fn compact(&self) {
        if let Some(ref db) = self.db {
            db.compact_range(None::<&[u8]>, None::<&[u8]>);
        }
    }

    /// Get approximate DB size in bytes
    pub fn db_size_estimate(&self) -> u64 {
        if let Some(ref db) = self.db {
            db.property_int_value("rocksdb.estimate-live-data-size")
                .unwrap_or(Some(0))
                .unwrap_or(0)
        } else {
            0
        }
    }
}

pub struct KeyImage;

impl KeyImage {
    /// Generate a key image from a string seed
    pub fn generate(input: &str) -> String {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_KeyImage_v2");
        h.update(input.as_bytes());
        hex::encode(h.finalize())
    }

    /// Generate key image from private key bytes ONLY (no tx hash!)
    /// Key image MUST be deterministic per private key alone.
    /// Including tx_hash would allow different images per tx = double-spend.
    pub fn generate_from_key(private_seed: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_KeyImage_v3_deterministic");
        h.update(private_seed);
        // DO NOT include tx_hash — same key must always give same image
        hex::encode(&h.finalize()[..32])
    }

    /// Check if a key image is in the seen list
    pub fn is_duplicate(image_hex: &str, seen: &[String]) -> bool {
        seen.iter().any(|s| s == image_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_deterministic() {
        let ki1 = KeyImage::generate("seed_123");
        let ki2 = KeyImage::generate("seed_123");
        assert_eq!(ki1, ki2);
    }

    #[test]
    fn generate_unique_per_input() {
        let ki1 = KeyImage::generate("key_a");
        let ki2 = KeyImage::generate("key_b");
        assert_ne!(ki1, ki2);
    }

    #[test]
    fn generate_from_key_deterministic() {
        let pk = [42u8; 32];
        let ki1 = KeyImage::generate_from_key(&pk);
        let ki2 = KeyImage::generate_from_key(&pk);
        assert_eq!(ki1, ki2);
    }

    #[test]
    fn different_keys_different_images() {
        let ki1 = KeyImage::generate_from_key(&[1u8; 32]);
        let ki2 = KeyImage::generate_from_key(&[2u8; 32]);
        assert_ne!(ki1, ki2);
    }

    #[test]
    fn duplicate_detection() {
        let ki = KeyImage::generate("test");
        let seen = vec![ki.clone()];
        assert!(KeyImage::is_duplicate(&ki, &seen));
        assert!(!KeyImage::is_duplicate("other", &seen));
    }

    #[test]
    fn store_marks_spent() {
        let mut store = KeyImageStore::new();
        assert!(!store.is_spent("ki_001"));
        store.mark_spent("ki_001");
        assert!(store.is_spent("ki_001"));
    }

    #[test]
    fn store_finds_batch_duplicate() {
        let mut store = KeyImageStore::new();
        store.mark_spent("existing");

        let batch = vec!["new1".into(), "existing".into(), "new2".into()];
        let dup = store.find_duplicate(&batch);
        assert_eq!(dup, Some("existing".to_string()));
    }

    #[test]
    fn store_finds_intra_batch_duplicate() {
        let store = KeyImageStore::new();
        let batch = vec!["a".into(), "b".into(), "a".into()]; // "a" appears twice
        let dup = store.find_duplicate(&batch);
        assert_eq!(dup, Some("a".to_string()));
    }
}
