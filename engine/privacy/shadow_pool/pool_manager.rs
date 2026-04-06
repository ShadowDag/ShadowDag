// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Shadow Pool Manager — Orchestrates the full shadow transaction lifecycle:
// routing, mixing, and emission of privacy-enhanced transactions.
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::transaction::transaction::Transaction;
use crate::engine::privacy::shadow_pool::shadow_pool::ShadowPool;
use crate::engine::privacy::shadow_pool::shadow_transaction::MixDelay;
use crate::engine::privacy::shadow_pool::mixer::ShadowMixer;

/// Privacy levels for transaction routing
#[derive(Clone, Debug)]
pub enum PrivacyLevel {
    /// Standard: 3 hops, medium delay
    Standard,
    /// High: 5 hops, long delay
    High,
    /// Maximum: 8 hops, long delay, extra decoys
    Maximum,
    /// Express: 1 hop, instant (minimal privacy, fast confirmation)
    Express,
}

impl PrivacyLevel {
    pub fn hops(&self) -> u8 {
        match self {
            PrivacyLevel::Standard => 3,
            PrivacyLevel::High     => 5,
            PrivacyLevel::Maximum  => 8,
            PrivacyLevel::Express  => 1,
        }
    }

    pub fn delay(&self) -> MixDelay {
        match self {
            PrivacyLevel::Standard => MixDelay::Medium,
            PrivacyLevel::High     => MixDelay::Long,
            PrivacyLevel::Maximum  => MixDelay::Long,
            PrivacyLevel::Express  => MixDelay::Instant,
        }
    }
}

pub struct ShadowPoolManager {
    pool: ShadowPool,
}

impl Default for ShadowPoolManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowPoolManager {
    pub fn new() -> Self {
        Self {
            pool: ShadowPool::new(),
        }
    }

    /// Route a transaction through the shadow pool with default privacy
    pub fn route(&mut self, tx: &Transaction) {
        self.route_with_privacy(tx, PrivacyLevel::Standard);
    }

    /// Route with a specific privacy level
    pub fn route_with_privacy(&mut self, tx: &Transaction, level: PrivacyLevel) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.pool.submit_with_privacy(
            tx.clone(),
            timestamp,
            level.delay(),
            level.hops(),
        );
    }

    /// Process the pool and return transactions ready for the DAG network
    pub fn mix_and_emit(&mut self) -> Vec<Transaction> {
        ShadowMixer::mix(&mut self.pool);
        self.pool.drain_ready()
    }

    /// Get pool statistics
    pub fn pool_size(&self) -> usize {
        self.pool.size()
    }

    pub fn ready_count(&self) -> usize {
        self.pool.ready_count()
    }

    pub fn total_mixed(&self) -> u64 {
        self.pool.total_mixed()
    }

    pub fn can_mix(&self) -> bool {
        self.pool.can_mix()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxInput, TxType};

    fn make_tx() -> Transaction {
        Transaction {
            hash: "test_tx_001".to_string(),
            inputs: vec![TxInput {
                txid: "prev".into(),
                index: 0,
                owner: "alice".into(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput { address: "bob".into(), amount: 500, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    #[test]
    fn route_adds_to_pool() {
        let mut mgr = ShadowPoolManager::new();
        mgr.route(&make_tx());
        assert_eq!(mgr.pool_size(), 1);
    }

    #[test]
    fn privacy_levels() {
        assert_eq!(PrivacyLevel::Standard.hops(), 3);
        assert_eq!(PrivacyLevel::High.hops(), 5);
        assert_eq!(PrivacyLevel::Maximum.hops(), 8);
        assert_eq!(PrivacyLevel::Express.hops(), 1);
    }
}
