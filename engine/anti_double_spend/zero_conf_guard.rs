// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Zero-Conf Guard — Detects Finney and Vector76 attacks on 0/1-confirmation
// transactions by monitoring for conflicting TXs across blocks and mempool.
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

/// Minimum confirmations before a TX is considered safe
pub const SAFE_CONFIRMATIONS: u64 = 6;

/// A potential double-spend conflict
#[derive(Debug, Clone)]
pub struct ConflictAlert {
    pub tx_hash_1:   String,
    pub tx_hash_2:   String,
    pub shared_input: String,
    pub confirmations_1: u64,
    pub confirmations_2: u64,
    pub alert_type:  ConflictType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConflictType {
    /// Finney: pre-mined block with conflicting TX
    Finney,
    /// Vector76: 1-conf double-spend via race
    Vector76,
    /// Generic: two TXs spending same input
    Generic,
}

/// Monitors for 0-conf and 1-conf double-spend attempts
/// Maximum entries per map to prevent DoS memory exhaustion
const MAX_MEMPOOL_INPUTS: usize = 500_000;
const MAX_BLOCK_INPUTS: usize = 1_000_000;
const MAX_ALERTS: usize = 10_000;

pub struct ZeroConfGuard {
    /// Input → TX hash mapping for mempool TXs
    mempool_inputs: HashMap<String, String>,
    /// Input → TX hash mapping for recent blocks (last N blocks)
    block_inputs:   HashMap<String, (String, u64)>, // (tx_hash, block_height)
    /// Detected conflicts
    alerts:         Vec<ConflictAlert>,
    /// Current chain height
    current_height: u64,
}

impl Default for ZeroConfGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroConfGuard {
    pub fn new() -> Self {
        Self {
            mempool_inputs: HashMap::new(),
            block_inputs:   HashMap::new(),
            alerts:         Vec::new(),
            current_height: 0,
        }
    }

    /// Register a mempool TX — check for conflicts
    pub fn on_mempool_tx(&mut self, tx_hash: &str, input_keys: &[String]) -> Option<ConflictAlert> {
        // Prevent unbounded growth — evict oldest entries if at capacity
        if self.mempool_inputs.len() >= MAX_MEMPOOL_INPUTS {
            let keys: Vec<String> = self.mempool_inputs.keys().take(MAX_MEMPOOL_INPUTS / 10).cloned().collect();
            for k in keys { self.mempool_inputs.remove(&k); }
        }
        if self.alerts.len() >= MAX_ALERTS {
            self.alerts.drain(..MAX_ALERTS / 2);
        }

        for key in input_keys {
            // Check against other mempool TXs
            if let Some(existing) = self.mempool_inputs.get(key) {
                if existing != tx_hash {
                    let alert = ConflictAlert {
                        tx_hash_1: existing.clone(),
                        tx_hash_2: tx_hash.to_string(),
                        shared_input: key.clone(),
                        confirmations_1: 0,
                        confirmations_2: 0,
                        alert_type: ConflictType::Generic,
                    };
                    self.alerts.push(alert.clone());
                    return Some(alert);
                }
            }

            // Check against recent block TXs (Finney/Vector76)
            if let Some((block_tx, height)) = self.block_inputs.get(key) {
                let confs = self.current_height.saturating_sub(*height);
                let alert_type = if confs == 0 {
                    ConflictType::Finney // Same height = pre-mined block
                } else if confs <= 1 {
                    ConflictType::Vector76 // 1-conf double-spend
                } else {
                    ConflictType::Generic
                };

                let alert = ConflictAlert {
                    tx_hash_1: block_tx.clone(),
                    tx_hash_2: tx_hash.to_string(),
                    shared_input: key.clone(),
                    confirmations_1: confs,
                    confirmations_2: 0,
                    alert_type,
                };
                self.alerts.push(alert.clone());
                return Some(alert);
            }

            self.mempool_inputs.insert(key.clone(), tx_hash.to_string());
        }
        None
    }

    /// Register a block TX — move from mempool tracking to block tracking
    pub fn on_block_tx(&mut self, tx_hash: &str, input_keys: &[String], block_height: u64) {
        // Update height only if this block is newer
        self.current_height = self.current_height.max(block_height);
        for key in input_keys {
            self.mempool_inputs.remove(key);
            self.block_inputs.insert(key.clone(), (tx_hash.to_string(), block_height));
        }
    }

    /// Prune old block inputs (only keep last SAFE_CONFIRMATIONS blocks)
    pub fn prune(&mut self) {
        if self.current_height <= SAFE_CONFIRMATIONS { return; }
        let cutoff = self.current_height - SAFE_CONFIRMATIONS;
        self.block_inputs.retain(|_, (_, h)| *h > cutoff);
    }

    /// Is a TX safe (enough confirmations)?
    pub fn is_safe(&self, _tx_hash: &str, confirmations: u64) -> bool {
        confirmations >= SAFE_CONFIRMATIONS
    }

    /// Get recent alerts
    pub fn recent_alerts(&self) -> &[ConflictAlert] { &self.alerts }
    pub fn alert_count(&self) -> usize { self.alerts.len() }
    pub fn clear_alerts(&mut self) { self.alerts.clear(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_conflict_for_unique_inputs() {
        let mut guard = ZeroConfGuard::new();
        let result = guard.on_mempool_tx("tx1", &["input_a".into()]);
        assert!(result.is_none());
    }

    #[test]
    fn detects_mempool_conflict() {
        let mut guard = ZeroConfGuard::new();
        guard.on_mempool_tx("tx1", &["input_a".into()]);
        let result = guard.on_mempool_tx("tx2", &["input_a".into()]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().alert_type, ConflictType::Generic);
    }

    #[test]
    fn detects_finney_attack() {
        let mut guard = ZeroConfGuard::new();
        guard.current_height = 100;
        guard.on_block_tx("block_tx", &["input_a".into()], 100);
        let result = guard.on_mempool_tx("mempool_tx", &["input_a".into()]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().alert_type, ConflictType::Finney);
    }

    #[test]
    fn detects_vector76() {
        let mut guard = ZeroConfGuard::new();
        guard.current_height = 101;
        guard.on_block_tx("block_tx", &["input_a".into()], 100); // 1 conf
        let result = guard.on_mempool_tx("attack_tx", &["input_a".into()]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().alert_type, ConflictType::Vector76);
    }

    #[test]
    fn safe_after_confirmations() {
        let guard = ZeroConfGuard::new();
        assert!(!guard.is_safe("tx", 1));
        assert!(guard.is_safe("tx", SAFE_CONFIRMATIONS));
    }

    #[test]
    fn prune_old_inputs() {
        let mut guard = ZeroConfGuard::new();
        guard.on_block_tx("old_tx", &["old_input".into()], 1);
        guard.current_height = 100;
        guard.prune();
        // Old input should be pruned
        assert!(!guard.block_inputs.contains_key("old_input"));
    }
}
