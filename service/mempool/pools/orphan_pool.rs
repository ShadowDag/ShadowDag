// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use crate::domain::transaction::transaction::Transaction;

pub const MAX_ORPHAN_AGE: u64 = 100;

pub const MAX_ORPHAN_COUNT: usize = 1_000;

pub struct OrphanPool {
    orphans:   HashMap<String, Vec<Transaction>>,
    /// Reverse index: tx.hash → list of bucket keys this tx was added to
    tx_buckets: HashMap<String, Vec<String>>,
    age_map:   HashMap<String, u64>,
    count:     usize,
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new()
    }
}

impl OrphanPool {
    pub fn new() -> Self {
        Self {
            orphans:    HashMap::new(),
            tx_buckets: HashMap::new(),
            age_map:    HashMap::new(),
            count:      0,
        }
    }

    pub fn add(&mut self, tx: Transaction, current_height: u64) -> bool {
        if self.count >= MAX_ORPHAN_COUNT {
            return false;
        }

        // BUG FIX: Dedup check — if this tx hash is already tracked, skip.
        // Without this, re-adding the same orphan increments count and
        // pushes duplicate entries into bucket vectors, inflating the pool
        // count and causing double-promotion.
        if self.tx_buckets.contains_key(&tx.hash) {
            return false;
        }

        let mut bucket_keys = Vec::new();
        for input in &tx.inputs {
            self.orphans
                .entry(input.txid.clone())
                .or_default()
                .push(tx.clone());
            bucket_keys.push(input.txid.clone());
        }

        let added = !bucket_keys.is_empty();
        if added {
            self.tx_buckets.insert(tx.hash.clone(), bucket_keys);
            self.age_map.insert(tx.hash.clone(), current_height);
            self.count += 1;
        }
        added
    }

    pub fn promote(&mut self, parent_txid: &str) -> Vec<Transaction> {
        let promoted = self.orphans.remove(parent_txid).unwrap_or_default();
        // Filter out TXs that were already promoted via a different parent bucket.
        // A TX with multiple inputs can appear in multiple orphan buckets (one per
        // parent). When parent A triggers promotion the TX is promoted and removed
        // from tx_buckets. If parent B later triggers, the same TX would appear
        // again without this filter.
        let promoted: Vec<Transaction> = promoted.into_iter()
            .filter(|tx| self.tx_buckets.contains_key(&tx.hash))
            .collect();
        for tx in &promoted {
            // Remove from all other buckets this tx was registered in
            if let Some(buckets) = self.tx_buckets.remove(&tx.hash) {
                for bucket_key in &buckets {
                    if bucket_key == parent_txid { continue; }
                    if let Some(bucket) = self.orphans.get_mut(bucket_key) {
                        bucket.retain(|t| t.hash != tx.hash);
                        if bucket.is_empty() {
                            self.orphans.remove(bucket_key);
                        }
                    }
                }
            }
            self.age_map.remove(&tx.hash);
            if self.count > 0 { self.count -= 1; }
        }
        promoted
    }

    pub fn evict_old(&mut self, current_height: u64) {
        let old_txids: Vec<String> = self.age_map
            .iter()
            .filter(|(_, &age)| current_height.saturating_sub(age) > MAX_ORPHAN_AGE)
            .map(|(k, _)| k.clone())
            .collect();

        for txid in &old_txids {
            self.age_map.remove(txid);
            // BUG FIX: Also clean up tx_buckets for evicted entries.
            // Without this, tx_buckets grows unboundedly with stale entries
            // that reference tx hashes no longer in any orphan bucket,
            // causing memory leaks and incorrect promote() behavior.
            self.tx_buckets.remove(txid);
            if self.count > 0 { self.count -= 1; }
        }

        self.orphans.retain(|_, txs| {
            txs.retain(|tx| !old_txids.contains(&tx.hash));
            !txs.is_empty()
        });
    }

    pub fn count(&self) -> usize { self.count }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput};

    fn make_tx(hash: &str, input_txids: Vec<&str>) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: input_txids.iter().enumerate().map(|(i, txid)| TxInput {
                txid: txid.to_string(),
                index: i as u32,
                owner: String::new(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
            }).collect(),
            outputs: vec![TxOutput {
                amount: 100,
                address: "addr1".to_string(),
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 10,
            timestamp: 1000,
            is_coinbase: false,
            tx_type: Default::default(),
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn add_and_count() {
        let mut pool = OrphanPool::new();
        let tx = make_tx("tx1", vec!["parent1"]);
        assert!(pool.add(tx, 0));
        assert_eq!(pool.count(), 1);
    }

    #[test]
    fn add_no_inputs_not_added() {
        let mut pool = OrphanPool::new();
        let mut tx = make_tx("tx1", vec!["p"]);
        tx.inputs.clear();
        assert!(!pool.add(tx, 0));
        assert_eq!(pool.count(), 0);
    }

    #[test]
    fn promote_returns_orphans() {
        let mut pool = OrphanPool::new();
        pool.add(make_tx("tx1", vec!["parent_a"]), 0);
        pool.add(make_tx("tx2", vec!["parent_a"]), 0);
        let promoted = pool.promote("parent_a");
        assert_eq!(promoted.len(), 2);
        assert_eq!(pool.count(), 0);
    }

    #[test]
    fn promote_unknown_returns_empty() {
        let mut pool = OrphanPool::new();
        let promoted = pool.promote("unknown");
        assert!(promoted.is_empty());
    }

    #[test]
    fn evict_old_removes_stale() {
        let mut pool = OrphanPool::new();
        pool.add(make_tx("old_tx", vec!["p1"]), 0);
        pool.add(make_tx("new_tx", vec!["p2"]), 200);
        pool.evict_old(200);
        // old_tx at height 0, current 200 → age 200 > MAX_ORPHAN_AGE(100) → evicted
        // new_tx at height 200, current 200 → age 0 → kept
        assert_eq!(pool.count(), 1);
    }

    #[test]
    fn max_capacity_rejects() {
        let mut pool = OrphanPool::new();
        for i in 0..MAX_ORPHAN_COUNT {
            pool.add(make_tx(&format!("tx_{}", i), vec!["p"]), 0);
        }
        assert_eq!(pool.count(), MAX_ORPHAN_COUNT);
        assert!(!pool.add(make_tx("overflow", vec!["p"]), 0));
    }
}
