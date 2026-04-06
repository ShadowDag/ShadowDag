// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::{BTreeMap, HashMap, HashSet};
use crate::errors::MempoolError;

#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub hash:        String,
    pub fee:         u64,
    pub fee_rate:    f64,
    pub size_bytes:  usize,
    pub input_keys:  Vec<String>,
    pub added_at:    u64,
}

impl MempoolEntry {
    pub fn new(hash: &str, fee: u64, size_bytes: usize, input_keys: Vec<String>, added_at: u64) -> Self {
        let fee_rate = if size_bytes > 0 { fee as f64 / size_bytes as f64 } else { 0.0 };
        Self { hash: hash.to_string(), fee, fee_rate, size_bytes, input_keys, added_at }
    }
}

pub struct MempoolIndex {
    entries:      HashMap<String, MempoolEntry>,

    fee_index:    BTreeMap<u64, HashSet<String>>,

    spend_index:  HashMap<String, String>,
}

impl Default for MempoolIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl MempoolIndex {
    pub fn new() -> Self {
        Self {
            entries:     HashMap::new(),
            fee_index:   BTreeMap::new(),
            spend_index: HashMap::new(),
        }
    }

    pub fn insert(&mut self, entry: MempoolEntry) -> Result<(), MempoolError> {
        for key in &entry.input_keys {
            if let Some(existing) = self.spend_index.get(key) {
                return Err(MempoolError::ConflictingInput(
                    format!("double spend: input {} already used by tx {}", key, existing)
                ));
            }
        }

        for key in &entry.input_keys {
            self.spend_index.insert(key.clone(), entry.hash.clone());
        }

        let fee_key = (entry.fee_rate * 1_000_000.0) as u64;
        self.fee_index.entry(fee_key).or_default().insert(entry.hash.clone());

        self.entries.insert(entry.hash.clone(), entry);
        Ok(())
    }

    pub fn remove(&mut self, hash: &str) -> bool {
        if let Some(entry) = self.entries.remove(hash) {
            for key in &entry.input_keys {
                self.spend_index.remove(key);
            }

            let fee_key = (entry.fee_rate * 1_000_000.0) as u64;
            if let Some(set) = self.fee_index.get_mut(&fee_key) {
                set.remove(hash);
                if set.is_empty() {
                    self.fee_index.remove(&fee_key);
                }
            }
            true
        } else {
            false
        }
    }

    pub fn top_by_fee(&self, count: usize) -> Vec<&MempoolEntry> {
        let mut result = Vec::with_capacity(count);
        for (_, hashes) in self.fee_index.iter().rev() {
            for hash in hashes {
                if result.len() >= count { break; }
                if let Some(e) = self.entries.get(hash) {
                    result.push(e);
                }
            }
            if result.len() >= count { break; }
        }
        result
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.entries.contains_key(hash)
    }

    pub fn get(&self, hash: &str) -> Option<&MempoolEntry> {
        self.entries.get(hash)
    }

    pub fn is_double_spend(&self, input_key: &str) -> bool {
        self.spend_index.contains_key(input_key)
    }

    pub fn count(&self) -> usize { self.entries.len() }

    pub fn total_fees(&self) -> u64 {
        self.entries.values()
            .try_fold(0u64, |acc, e| acc.checked_add(e.fee))
            .unwrap_or(u64::MAX)
    }

    pub fn total_size_bytes(&self) -> usize {
        self.entries.values().map(|e| e.size_bytes).sum()
    }

    pub fn min_fee_rate(&self) -> f64 {
        self.entries.values().map(|e| e.fee_rate).fold(f64::MAX, f64::min)
            .min(f64::MAX)
    }

    pub fn max_fee_rate(&self) -> f64 {
        self.entries.values().map(|e| e.fee_rate).fold(0.0_f64, f64::max)
    }

    pub fn evict_older_than(&mut self, cutoff_timestamp: u64) -> usize {
        let old: Vec<String> = self.entries.values()
            .filter(|e| e.added_at < cutoff_timestamp)
            .map(|e| e.hash.clone())
            .collect();
        let count = old.len();
        for hash in old { self.remove(&hash); }
        count
    }

    pub fn evict_lowest_fee(&mut self, count: usize) -> usize {
        let lowest: Vec<String> = self.fee_index.values()
            .flat_map(|s| s.iter().cloned())
            .take(count)
            .collect();
        let c = lowest.len();
        for hash in lowest { self.remove(&hash); }
        c
    }

    pub fn all_hashes(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(hash: &str, fee: u64, size: usize) -> MempoolEntry {
        MempoolEntry::new(hash, fee, size, vec![format!("prev:{}:0", hash)], 1000)
    }

    #[test]
    fn insert_and_contains() {
        let mut idx = MempoolIndex::new();
        idx.insert(make_entry("tx1", 100, 200)).unwrap();
        assert!(idx.contains("tx1"));
    }

    #[test]
    fn remove_works() {
        let mut idx = MempoolIndex::new();
        idx.insert(make_entry("tx2", 50, 100)).unwrap();
        assert!(idx.remove("tx2"));
        assert!(!idx.contains("tx2"));
    }

    #[test]
    fn double_spend_rejected() {
        let mut idx = MempoolIndex::new();
        let e1 = MempoolEntry::new("tx1", 100, 200, vec!["utxo:0".into()], 1000);
        let e2 = MempoolEntry::new("tx2", 200, 200, vec!["utxo:0".into()], 1001);
        idx.insert(e1).unwrap();
        assert!(idx.insert(e2).is_err());
    }

    #[test]
    fn top_by_fee_returns_highest_first() {
        let mut idx = MempoolIndex::new();
        idx.insert(MempoolEntry::new("low",  10,  200, vec!["u1:0".into()], 1000)).unwrap();
        idx.insert(MempoolEntry::new("high", 500, 200, vec!["u2:0".into()], 1000)).unwrap();
        let top = idx.top_by_fee(1);
        assert_eq!(top[0].hash, "high");
    }

    #[test]
    fn total_fees_sums_correctly() {
        let mut idx = MempoolIndex::new();
        idx.insert(MempoolEntry::new("a", 100, 200, vec!["ua:0".into()], 1000)).unwrap();
        idx.insert(MempoolEntry::new("b", 200, 200, vec!["ub:0".into()], 1000)).unwrap();
        assert_eq!(idx.total_fees(), 300);
    }

    #[test]
    fn evict_older_than_removes_old() {
        let mut idx = MempoolIndex::new();
        idx.insert(MempoolEntry::new("old", 100, 200, vec!["uo:0".into()], 500)).unwrap();
        idx.insert(MempoolEntry::new("new", 100, 200, vec!["un:0".into()], 2000)).unwrap();
        let evicted = idx.evict_older_than(1000);
        assert_eq!(evicted, 1);
        assert!(!idx.contains("old"));
        assert!(idx.contains("new"));
    }
}
