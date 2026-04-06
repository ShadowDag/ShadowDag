// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rocksdb::{DB, Options, WriteBatch};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use crate::errors::{DagError, StorageError};

const ORDER_PREFIX: &str = "order:";

pub struct OrderingStore {
    db: DB,
}

impl OrderingStore {
    pub fn new(path: &str) -> Option<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);

        opts.increase_parallelism(4);
        opts.set_max_open_files(1000);

        match DB::open(&opts, Path::new(path)) {
            Ok(db) => Some(Self { db }),
            Err(e) => {
                eprintln!("[OrderingStore] DB open error: {}", e);
                None
            }
        }
    }

    pub fn new_required(path: &str) -> Result<Self, DagError> {
        Self::new(path).ok_or_else(|| {
            StorageError::OpenFailed { path: path.to_string(), reason: "cannot open DB".to_string() }.into()
        })
    }

    #[inline]
    fn make_key(hash: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(ORDER_PREFIX.len() + hash.len());
        key.extend_from_slice(ORDER_PREFIX.as_bytes());
        key.extend_from_slice(hash.as_bytes());
        key
    }

    pub fn set_order(&self, hash: &str, order: u64) {
        let key = Self::make_key(hash);

        if let Err(e) = self.db.put(&key, order.to_be_bytes()) {
            eprintln!("[OrderingStore] DB write failed: {}", e);
        }
    }

    pub fn get_order(&self, hash: &str) -> Option<u64> {
        let key = Self::make_key(hash);

        match self.db.get(&key) {
            Ok(Some(bytes)) if bytes.len() >= 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes[..8]);
                Some(u64::from_be_bytes(arr))
            }
            Ok(_) => None,
            Err(e) => {
                eprintln!("[OrderingStore] DB read error: {}", e);
                None
            }
        }
    }

    pub fn order_blocks(
        &self,
        blocks: &[String],
        all_blocks: &HashMap<String, Vec<String>>,
        ghostdag: &crate::engine::dag::ghostdag::ghostdag::GhostDag,
    ) -> Vec<String> {
        let block_set: HashSet<&str> = blocks.iter().map(|s| s.as_str()).collect();

        let mut in_degree: HashMap<String, usize> = HashMap::with_capacity(blocks.len());
        let mut child_map: HashMap<String, Vec<String>> = HashMap::with_capacity(blocks.len());

        let mut blue_cache: HashMap<String, u64> = HashMap::with_capacity(blocks.len());

        for b in blocks {
            blue_cache.insert(b.clone(), ghostdag.get_blue_score(b));
            in_degree.insert(b.clone(), 0);
        }

        for b in blocks {
            if let Some(parents) = all_blocks.get(b) {
                for p in parents {
                    if block_set.contains(p.as_str()) {
                        if let Some(d) = in_degree.get_mut(b) {
                            *d += 1;
                        }
                        child_map.entry(p.clone()).or_default().push(b.clone());
                    }
                }
            }
        }

        let mut frontier: VecDeque<String> = blocks
            .iter()
            .filter(|b| *in_degree.get(*b).unwrap_or(&0) == 0)
            .cloned()
            .collect();

        Self::sort_frontier(&mut frontier, &blue_cache);

        let mut ordered = Vec::with_capacity(blocks.len());

        while let Some(current) = frontier.pop_front() {
            ordered.push(current.clone());

            if let Some(children) = child_map.get(&current) {
                let mut next_level = Vec::with_capacity(children.len());

                for child in children {
                    if let Some(d) = in_degree.get_mut(child) {
                        if *d > 0 {
                            *d -= 1;
                        }

                        if *d == 0 {
                            next_level.push(child.clone());
                        }
                    }
                }

                Self::sort_vec(&mut next_level, &blue_cache);

                
                for item in next_level {
                    let si = *blue_cache.get(&item).unwrap_or(&0);

                    let pos = {
                        let slice = frontier.make_contiguous();
                        slice
                            .binary_search_by(|x| {
                                let sx = *blue_cache.get(x).unwrap_or(&0);
                                sx.cmp(&si).then_with(|| x.cmp(&item))
                            })
                            .unwrap_or_else(|e| e)
                    };

                    frontier.insert(pos, item);
                }
            }
        }

        if ordered.len() != blocks.len() {
            eprintln!(
                "[OrderingStore] WARNING: Cycle detected! ordered={} expected={}",
                ordered.len(),
                blocks.len()
            );
        }

        ordered
    }

    pub fn sort_by_blue_score(
        &self,
        mut blocks: Vec<String>,
        ghostdag: &crate::engine::dag::ghostdag::ghostdag::GhostDag,
    ) -> Vec<String> {
        let mut blue_cache = HashMap::with_capacity(blocks.len());

        for b in &blocks {
            blue_cache.insert(b.clone(), ghostdag.get_blue_score(b));
        }

        blocks.sort_unstable_by(|a, b| {
            let sa = *blue_cache.get(a).unwrap_or(&0);
            let sb = *blue_cache.get(b).unwrap_or(&0);
            sa.cmp(&sb).then_with(|| a.cmp(b))
        });

        blocks
    }

    pub fn sort_and_store(
        &self,
        blocks: Vec<String>,
        ghostdag: &crate::engine::dag::ghostdag::ghostdag::GhostDag,
    ) -> Vec<String> {
        let sorted = self.sort_by_blue_score(blocks, ghostdag);

        let mut batch = WriteBatch::default();

        for (idx, hash) in sorted.iter().enumerate() {
            let key = Self::make_key(hash);
            batch.put(&key, (idx as u64).to_be_bytes());
        }

        if let Err(e) = self.db.write(batch) {
            eprintln!("[OrderingStore] batch write failed: {}", e);
        }

        sorted
    }

    pub fn order_and_store(
        &self,
        blocks: &[String],
        all_blocks: &HashMap<String, Vec<String>>,
        ghostdag: &crate::engine::dag::ghostdag::ghostdag::GhostDag,
    ) -> Vec<String> {
        let ordered = self.order_blocks(blocks, all_blocks, ghostdag);

        let mut batch = WriteBatch::default();

        for (idx, hash) in ordered.iter().enumerate() {
            let key = Self::make_key(hash);
            batch.put(&key, (idx as u64).to_be_bytes());
        }

        if let Err(e) = self.db.write(batch) {
            eprintln!("[OrderingStore] batch write failed: {}", e);
        }

        ordered
    }

    fn sort_vec(vec: &mut [String], blue_cache: &HashMap<String, u64>) {
        vec.sort_unstable_by(|a, b| {
            let sa = *blue_cache.get(a).unwrap_or(&0);
            let sb = *blue_cache.get(b).unwrap_or(&0);
            sa.cmp(&sb).then_with(|| a.cmp(b))
        });
    }

    fn sort_frontier(frontier: &mut VecDeque<String>, blue_cache: &HashMap<String, u64>) {
        let mut temp: Vec<_> = frontier.drain(..).collect();

        temp.sort_unstable_by(|a, b| {
            let sa = *blue_cache.get(a).unwrap_or(&0);
            let sb = *blue_cache.get(b).unwrap_or(&0);
            sa.cmp(&sb).then_with(|| a.cmp(b))
        });

        frontier.extend(temp);
    }
}