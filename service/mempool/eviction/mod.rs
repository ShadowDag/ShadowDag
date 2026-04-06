// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::time::{SystemTime, UNIX_EPOCH};
use crate::config::consensus::mempool_config::MempoolConfig;

pub const MAX_MEMPOOL_SIZE:    usize = MempoolConfig::MAX_MEMPOOL_SIZE;
pub const MAX_MEMPOOL_BYTES:   usize = MempoolConfig::MAX_MEMPOOL_BYTES;
pub const TX_MAX_AGE_SECS:     u64   = MempoolConfig::MAX_MEMPOOL_TX_AGE_SECS;
pub const EVICTION_BATCH_SIZE: usize = MempoolConfig::EVICTION_BATCH_SIZE;
pub const MIN_FEE_RATE:        f64   = MempoolConfig::MIN_FEE_RATE;

#[derive(Debug, Clone)]
pub struct EvictableEntry {
    pub hash:       String,
    pub fee_rate:   f64,
    pub added_at:   u64,
    pub size_bytes: usize,
}

impl EvictableEntry {
    pub fn new(hash: &str, fee: u64, size_bytes: usize, added_at: u64) -> Self {
        let fee_rate = if size_bytes > 0 { fee as f64 / size_bytes as f64 } else { 0.0 };
        Self {
            hash:    hash.to_string(),
            fee_rate,
            added_at,
            size_bytes,
        }
    }

    pub fn age_secs(&self) -> u64 {
        now_secs().saturating_sub(self.added_at)
    }

    pub fn is_expired(&self) -> bool {
        self.age_secs() > TX_MAX_AGE_SECS
    }

    pub fn is_low_fee(&self) -> bool {
        self.fee_rate < MIN_FEE_RATE
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EvictionPolicy {
    Oldest,
    LowestFee,
    Mixed,
}

pub struct EvictionResult {
    pub evicted:      Vec<String>,
    pub by_age:       usize,
    pub by_fee:       usize,
    pub freed_bytes:  usize,
}

pub struct MempoolEviction;

impl MempoolEviction {
    pub fn select_evictable(
        entries:     &[EvictableEntry],
        policy:      &EvictionPolicy,
        target_free: usize,
    ) -> EvictionResult {
        let mut to_evict: Vec<&EvictableEntry> = Vec::new();

        match policy {
            EvictionPolicy::Oldest => {
                let mut sorted: Vec<&EvictableEntry> = entries.iter().collect();
                sorted.sort_by_key(|e| e.added_at);
                for e in sorted.iter().take(EVICTION_BATCH_SIZE) {
                    to_evict.push(e);
                }
            }
            EvictionPolicy::LowestFee => {
                let mut sorted: Vec<&EvictableEntry> = entries.iter().collect();
                sorted.sort_by(|a, b| a.fee_rate.partial_cmp(&b.fee_rate).unwrap_or(std::cmp::Ordering::Equal));
                for e in sorted.iter().take(EVICTION_BATCH_SIZE) {
                    to_evict.push(e);
                }
            }
            EvictionPolicy::Mixed => {
                let expired: Vec<&EvictableEntry> = entries.iter()
                    .filter(|e| e.is_expired())
                    .collect();

                let low_fee: Vec<&EvictableEntry> = entries.iter()
                    .filter(|e| !e.is_expired() && e.is_low_fee())
                    .collect();

                to_evict.extend(expired);
                to_evict.extend(low_fee);
                to_evict.truncate(EVICTION_BATCH_SIZE);
            }
        }

        let mut freed = 0usize;
        let mut by_age = 0usize;
        let mut by_fee = 0usize;
        let mut evicted = Vec::new();

        for e in to_evict {
            if freed >= target_free { break; }
            freed += e.size_bytes;
            evicted.push(e.hash.clone());
            if e.is_expired()  { by_age += 1; }
            else               { by_fee += 1; }
        }

        EvictionResult { evicted, by_age, by_fee, freed_bytes: freed }
    }

    pub fn needs_eviction(count: usize, total_bytes: usize) -> bool {
        count >= MAX_MEMPOOL_SIZE || total_bytes >= MAX_MEMPOOL_BYTES
    }

    pub fn bytes_to_free(total_bytes: usize) -> usize {
        if total_bytes <= MAX_MEMPOOL_BYTES {
            return 0;
        }
        total_bytes - (MAX_MEMPOOL_BYTES * 9 / 10)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(hash: &str, fee_rate: f64, age_secs: u64) -> EvictableEntry {
        let fee = (fee_rate * 200.0) as u64;
        EvictableEntry::new(hash, fee, 200, now_secs().saturating_sub(age_secs))
    }

    #[test]
    fn oldest_evicted_first() {
        let entries = vec![
            entry("new",  5.0, 100),
            entry("old",  5.0, 50_000),
        ];
        let res = MempoolEviction::select_evictable(&entries, &EvictionPolicy::Oldest, usize::MAX);
        assert_eq!(res.evicted[0], "old");
    }

    #[test]
    fn lowest_fee_evicted_first() {
        let entries = vec![
            entry("high", 100.0, 100),
            entry("low",    0.1, 100),
        ];
        let res = MempoolEviction::select_evictable(&entries, &EvictionPolicy::LowestFee, usize::MAX);
        assert_eq!(res.evicted[0], "low");
    }

    #[test]
    fn mixed_removes_expired() {
        let entries = vec![
            entry("expired", 1.0, TX_MAX_AGE_SECS + 100),
            entry("fresh",   1.0, 100),
        ];
        let res = MempoolEviction::select_evictable(&entries, &EvictionPolicy::Mixed, usize::MAX);
        assert!(res.evicted.contains(&"expired".to_string()));
    }

    #[test]
    fn needs_eviction_at_max_size() {
        assert!(MempoolEviction::needs_eviction(MAX_MEMPOOL_SIZE, 0));
    }

    #[test]
    fn bytes_to_free_zero_when_under_limit() {
        assert_eq!(MempoolEviction::bytes_to_free(100), 0);
    }

    #[test]
    fn is_expired_after_timeout() {
        let e = entry("tx", 1.0, TX_MAX_AGE_SECS + 10);
        assert!(e.is_expired());
    }

    #[test]
    fn not_expired_when_fresh() {
        let e = entry("tx", 1.0, 3600);
        assert!(!e.is_expired());
    }
}
