// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};

pub const DEFAULT_CACHE_SIZE: usize = 1_024;
pub const MAX_CACHE_SIZE: usize = 16_384;

#[derive(Debug, Clone)]
pub struct CachedBlock {
    pub hash: String,
    pub height: u64,
    pub raw_data: Vec<u8>,
    pub access_count: u64,
}

struct BlockCacheInner {
    entries: HashMap<String, CachedBlock>,
    lru_queue: VecDeque<String>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

impl BlockCacheInner {
    fn touch(&mut self, hash: &str) {
        self.lru_queue.retain(|h| h != hash);
        self.lru_queue.push_back(hash.to_string());
        if let Some(entry) = self.entries.get_mut(hash) {
            entry.access_count += 1;
        }
    }

    fn evict_lru(&mut self) {
        if let Some(oldest) = self.lru_queue.pop_front() {
            self.entries.remove(&oldest);
        }
    }
}

/// Thread-safe LRU block cache using `parking_lot::RwLock`.
pub struct BlockCache {
    inner: RwLock<BlockCacheInner>,
}

impl BlockCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(BlockCacheInner {
                entries: HashMap::new(),
                lru_queue: VecDeque::new(),
                capacity: capacity.clamp(1, MAX_CACHE_SIZE),
                hits: 0,
                misses: 0,
            }),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Self {
        Self::new(DEFAULT_CACHE_SIZE)
    }

    pub fn insert(&self, hash: &str, height: u64, raw_data: Vec<u8>) {
        let mut inner = self.inner.write();
        if let Some(existing) = inner.entries.get_mut(hash) {
            // Update existing entry with potentially newer data
            existing.height = height;
            existing.raw_data = raw_data;
            inner.touch(hash);
            return;
        }

        while inner.entries.len() >= inner.capacity {
            inner.evict_lru();
        }

        inner.lru_queue.push_back(hash.to_string());
        inner.entries.insert(
            hash.to_string(),
            CachedBlock {
                hash: hash.to_string(),
                height,
                raw_data,
                access_count: 0,
            },
        );
    }

    /// Get a block from cache, updating LRU order. Returns a clone.
    pub fn get(&self, hash: &str) -> Option<CachedBlock> {
        let mut inner = self.inner.write();
        if inner.entries.contains_key(hash) {
            inner.touch(hash);
            inner.hits += 1;
            inner.entries.get(hash).cloned()
        } else {
            inner.misses += 1;
            None
        }
    }

    pub fn peek(&self, hash: &str) -> Option<CachedBlock> {
        let inner = self.inner.read();
        inner.entries.get(hash).cloned()
    }

    pub fn contains(&self, hash: &str) -> bool {
        let inner = self.inner.read();
        inner.entries.contains_key(hash)
    }

    pub fn remove(&self, hash: &str) -> bool {
        let mut inner = self.inner.write();
        if inner.entries.remove(hash).is_some() {
            inner.lru_queue.retain(|h| h != hash);
            return true;
        }
        false
    }

    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.entries.clear();
        inner.lru_queue.clear();
        // Reset hit/miss counters so stats reflect post-clear state
        inner.hits = 0;
        inner.misses = 0;
    }

    pub fn size(&self) -> usize {
        self.inner.read().entries.len()
    }
    pub fn capacity(&self) -> usize {
        self.inner.read().capacity
    }
    pub fn is_full(&self) -> bool {
        let inner = self.inner.read();
        inner.entries.len() >= inner.capacity
    }

    pub fn hits(&self) -> u64 {
        self.inner.read().hits
    }
    pub fn misses(&self) -> u64 {
        self.inner.read().misses
    }

    pub fn hit_rate(&self) -> f64 {
        let inner = self.inner.read();
        let total = inner.hits + inner.misses;
        if total == 0 {
            return 0.0;
        }
        inner.hits as f64 / total as f64
    }

    pub fn set_capacity(&self, new_cap: usize) {
        let mut inner = self.inner.write();
        inner.capacity = new_cap.clamp(1, MAX_CACHE_SIZE);

        while inner.entries.len() > inner.capacity {
            inner.evict_lru();
        }
    }
}

// BlockCache is now Send + Sync via RwLock
unsafe impl Send for BlockCache {}
unsafe impl Sync for BlockCache {}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_data(n: u8) -> Vec<u8> {
        vec![n; 100]
    }

    #[test]
    fn insert_and_contains() {
        let cache = BlockCache::new(10);
        cache.insert("h1", 1, block_data(1));
        assert!(cache.contains("h1"));
    }

    #[test]
    fn get_returns_block() {
        let cache = BlockCache::new(10);
        cache.insert("h1", 1, block_data(1));
        assert!(cache.get("h1").is_some());
        assert_eq!(cache.hits(), 1);
    }

    #[test]
    fn miss_increments_misses() {
        let cache = BlockCache::new(10);
        cache.get("nonexistent");
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn lru_evicts_oldest() {
        let cache = BlockCache::new(2);
        cache.insert("h1", 1, block_data(1));
        cache.insert("h2", 2, block_data(2));
        cache.insert("h3", 3, block_data(3));
        assert!(!cache.contains("h1"));
        assert!(cache.contains("h2"));
        assert!(cache.contains("h3"));
    }

    #[test]
    fn touch_updates_lru_order() {
        let cache = BlockCache::new(2);
        cache.insert("h1", 1, block_data(1));
        cache.insert("h2", 2, block_data(2));
        cache.get("h1");
        cache.insert("h3", 3, block_data(3));
        assert!(cache.contains("h1"));
        assert!(!cache.contains("h2"));
    }

    #[test]
    fn remove_works() {
        let cache = BlockCache::new(10);
        cache.insert("h1", 1, block_data(1));
        cache.remove("h1");
        assert!(!cache.contains("h1"));
    }

    #[test]
    fn hit_rate_correct() {
        let cache = BlockCache::new(10);
        cache.insert("h1", 1, block_data(1));
        cache.get("h1");
        cache.get("miss");
        assert!((cache.hit_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn concurrent_access_safe() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(BlockCache::new(100));
        let mut handles = vec![];

        // Spawn 4 writer threads
        for t in 0..4u8 {
            let c = cache.clone();
            handles.push(thread::spawn(move || {
                for i in 0..25u8 {
                    let key = format!("t{}_h{}", t, i);
                    c.insert(&key, i as u64, vec![t; 50]);
                }
            }));
        }

        // Spawn 4 reader threads
        for t in 0..4u8 {
            let c = cache.clone();
            handles.push(thread::spawn(move || {
                for i in 0..25u8 {
                    let key = format!("t{}_h{}", t, i);
                    let _ = c.get(&key);
                    let _ = c.contains(&key);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
        assert!(cache.size() <= 100);
    }
}
