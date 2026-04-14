// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Shadow Transactions — Transactions that pass through the Shadow Pool
// mixing layer before entering the DAG network. This breaks the link
// between sender and the transaction visible on-chain.
//
// Flow: User -> Shadow Pool -> Mix -> DAG Network
// ═══════════════════════════════════════════════════════════════════════════

use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::domain::transaction::transaction::Transaction;

/// Delay tiers for shadow transaction mixing
#[derive(Clone, Debug, PartialEq)]
pub enum MixDelay {
    /// Immediate (no delay, just obfuscation)
    Instant,
    /// Short delay (1-5 seconds)
    Short,
    /// Medium delay (5-30 seconds)
    Medium,
    /// Long delay (30-120 seconds) — maximum privacy
    Long,
}

impl MixDelay {
    pub fn max_delay_ms(&self) -> u64 {
        match self {
            MixDelay::Instant => 0,
            MixDelay::Short => 5_000,
            MixDelay::Medium => 30_000,
            MixDelay::Long => 120_000,
        }
    }
}

/// A transaction wrapped with shadow pool metadata
#[derive(Debug, Clone)]
pub struct ShadowTransaction {
    /// The original transaction
    pub tx: Transaction,
    /// When the transaction entered the shadow pool
    pub timestamp: u64,
    /// Whether the transaction has been mixed
    pub mixed: bool,
    /// Unique shadow ID (prevents correlation)
    pub shadow_id: String,
    /// Delay tier for this transaction
    pub delay: MixDelay,
    /// Number of hops through relay nodes
    pub hop_count: u8,
    /// Maximum hops before exiting shadow pool
    pub max_hops: u8,
    /// Whether this transaction is ready to exit the shadow pool
    pub ready_to_emit: bool,
    /// True if this is a decoy (dummy TX for batch padding).
    /// Decoys are filtered out at the network emission layer.
    pub is_decoy: bool,
}

impl ShadowTransaction {
    pub fn new(tx: Transaction, timestamp: u64) -> Self {
        let shadow_id = Self::generate_shadow_id(&tx.hash, timestamp);
        Self {
            tx,
            timestamp,
            mixed: false,
            shadow_id,
            delay: MixDelay::Medium,
            hop_count: 0,
            max_hops: 3,
            ready_to_emit: false,
            is_decoy: false,
        }
    }

    /// Create a decoy (dummy) transaction for batch padding.
    /// Uses a random hash and empty inputs/outputs so it is
    /// indistinguishable in size from real shadow transactions.
    pub fn new_decoy(timestamp: u64) -> Self {
        use crate::domain::transaction::transaction::{TxOutput, TxType};
        use rand::Rng;

        // Add random jitter (0-60s in ms) so decoys don't share identical timestamps
        let jitter: u64 = rand::thread_rng().gen_range(0..60_000);
        let decoy_ts = timestamp.wrapping_add(jitter);

        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let decoy_hash = hex::encode(entropy);

        let tx = Transaction {
            hash: decoy_hash.clone(),
            inputs: vec![],
            outputs: vec![TxOutput {
                // Decoy addresses use network-neutral format (filtered before relay)
                address: format!("DECOY{:0>40}", &decoy_hash[..40]),
                amount: 0,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 0,
            timestamp: decoy_ts,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };

        let shadow_id = Self::generate_shadow_id(&decoy_hash, decoy_ts);
        Self {
            tx,
            timestamp: decoy_ts,
            mixed: true,
            shadow_id,
            delay: MixDelay::Instant,
            hop_count: 0,
            max_hops: 0,
            ready_to_emit: true,
            is_decoy: true,
        }
    }

    pub fn with_delay(mut self, delay: MixDelay) -> Self {
        self.delay = delay;
        self
    }

    pub fn with_max_hops(mut self, max_hops: u8) -> Self {
        self.max_hops = max_hops.clamp(1, 10);
        self
    }

    /// Mark this transaction as mixed (obfuscation applied)
    pub fn mark_mixed(&mut self) {
        self.mixed = true;
        self.hop_count += 1;
        // Regenerate shadow ID after each mix to break correlation
        self.shadow_id =
            Self::generate_shadow_id(&self.shadow_id, self.timestamp + self.hop_count as u64);

        if self.hop_count >= self.max_hops {
            self.ready_to_emit = true;
        }
    }

    /// Check if this transaction should exit the shadow pool
    pub fn should_emit(&self, current_time: u64) -> bool {
        if self.ready_to_emit {
            return true;
        }
        // Also emit if max delay has passed
        let age = current_time.saturating_sub(self.timestamp);
        age >= self.delay.max_delay_ms()
    }

    /// Generate a unique, unlinkable shadow ID
    fn generate_shadow_id(seed: &str, timestamp: u64) -> String {
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);

        let mut h = Sha256::new();
        h.update(b"ShadowDAG_ShadowID_v1");
        h.update(seed.as_bytes());
        h.update(timestamp.to_le_bytes());
        h.update(entropy);
        hex::encode(&h.finalize()[..16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};

    fn make_tx() -> Transaction {
        Transaction {
            hash: "abc123".to_string(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "addr".into(),
                amount: 100,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn new_shadow_tx_is_unmixed() {
        let stx = ShadowTransaction::new(make_tx(), 1000);
        assert!(!stx.mixed);
        assert!(!stx.ready_to_emit);
        assert_eq!(stx.hop_count, 0);
    }

    #[test]
    fn mark_mixed_increments_hops() {
        let mut stx = ShadowTransaction::new(make_tx(), 1000);
        stx.mark_mixed();
        assert!(stx.mixed);
        assert_eq!(stx.hop_count, 1);
    }

    #[test]
    fn ready_after_max_hops() {
        let mut stx = ShadowTransaction::new(make_tx(), 1000).with_max_hops(2);
        stx.mark_mixed();
        assert!(!stx.ready_to_emit);
        stx.mark_mixed();
        assert!(stx.ready_to_emit);
    }

    #[test]
    fn shadow_id_changes_after_mix() {
        let mut stx = ShadowTransaction::new(make_tx(), 1000);
        let id1 = stx.shadow_id.clone();
        stx.mark_mixed();
        assert_ne!(id1, stx.shadow_id);
    }

    #[test]
    fn should_emit_after_delay() {
        let stx = ShadowTransaction::new(make_tx(), 1000).with_delay(MixDelay::Short);
        assert!(!stx.should_emit(2000)); // only 1s passed
        assert!(stx.should_emit(7000)); // 6s passed > 5s max
    }
}
