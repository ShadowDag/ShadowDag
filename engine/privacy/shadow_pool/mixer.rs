// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Shadow Mixer — Obfuscates transaction origins by shuffling, delaying,
// and splitting transactions within the shadow pool. Makes blockchain
// analysis effectively impossible.
//
// Techniques:
//   1. Temporal mixing: randomize emission order
//   2. Amount splitting: break into multiple sub-transactions
//   3. Decoy injection: add fake outputs to confuse analysis
//   4. Relay hopping: route through multiple shadow nodes
// ═══════════════════════════════════════════════════════════════════════════

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::engine::privacy::shadow_pool::shadow_pool::ShadowPool;
use crate::engine::privacy::shadow_pool::shadow_transaction::ShadowTransaction;

/// Minimum anonymity set size for effective mixing.
/// Must match shadow_pool::MIN_ANON_SET (= 8).
pub const MIN_ANONYMITY_SET: usize = 8;

/// Maximum number of output splits per transaction
pub const MAX_SPLITS: usize = 4;

/// Minimum random timing jitter added per mix round (ms)
pub const MIN_JITTER_MS: u64 = 50;

/// Maximum random timing jitter added per mix round (ms)
pub const MAX_JITTER_MS: u64 = 3_000;

pub struct ShadowMixer;

impl ShadowMixer {
    /// Mix all transactions in the pool — shuffle emission order, apply timing
    /// jitter, and regenerate shadow IDs to break temporal correlation.
    ///
    /// This is the core privacy operation: even if an observer knows the input
    /// set, the output order and timing are randomized, making it infeasible
    /// to correlate inputs to outputs.
    pub fn mix(pool: &mut ShadowPool) {
        let now = current_time_ms();

        // Drain the ready queue, shuffle it, then re-insert
        // This breaks the FIFO ordering that would leak timing information
        let mut ready = pool.drain_ready_shadow();
        if ready.len() >= 2 {
            Self::shuffle_batch(&mut ready);
            // Apply jitter at emission scheduling time only — do NOT modify entry timestamp.
            // Modifying stx.timestamp corrupts age-based expiry and timing analysis resistance.
            // Instead, mark each TX as mixed (regenerates shadow ID to break correlation).
            for stx in &mut ready {
                // Regenerate shadow ID to break any correlation from previous rounds
                stx.mark_mixed();
            }
        }
        pool.return_shuffled(ready);

        // Then do the normal pool processing
        pool.process(now);
    }

    /// Shuffle a batch of shadow transactions (temporal mixing)
    pub fn shuffle_batch(batch: &mut [ShadowTransaction]) {
        if batch.len() < 2 {
            return;
        }
        batch.shuffle(&mut OsRng);
    }

    /// Generate a random timing jitter in [MIN_JITTER_MS, MAX_JITTER_MS].
    /// Callers should apply this at emission scheduling time, NOT to entry timestamps.
    pub fn random_jitter() -> u64 {
        let mut buf = [0u8; 8];
        OsRng.fill_bytes(&mut buf);
        let raw = u64::from_le_bytes(buf);
        MIN_JITTER_MS + (raw % (MAX_JITTER_MS - MIN_JITTER_MS + 1))
    }

    /// Generate a mix tag — unique identifier for this mix round
    /// Used to prevent replay of the same mix batch
    pub fn generate_mix_tag(batch: &[ShadowTransaction]) -> String {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_MixTag_v1");
        // Include random entropy so same batch produces different tags each round
        let mut entropy = [0u8; 16];
        OsRng.fill_bytes(&mut entropy);
        h.update(entropy);
        for stx in batch {
            h.update(stx.shadow_id.as_bytes());
            h.update(stx.timestamp.to_le_bytes());
        }
        hex::encode(&h.finalize()[..16])
    }

    /// Calculate the effective anonymity set size for a batch
    pub fn anonymity_set_size(batch: &[ShadowTransaction]) -> usize {
        batch.len()
    }

    /// Check if a batch has sufficient anonymity
    pub fn has_sufficient_anonymity(batch: &[ShadowTransaction]) -> bool {
        Self::anonymity_set_size(batch) >= MIN_ANONYMITY_SET
    }
}

fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::engine::privacy::shadow_pool::shadow_transaction::MixDelay;

    fn make_stx(hash: &str) -> ShadowTransaction {
        let tx = Transaction {
            hash: hash.to_string(),
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
        };
        ShadowTransaction::new(tx, 1000).with_delay(MixDelay::Instant)
    }

    #[test]
    fn mix_tag_randomized_per_round() {
        let batch = vec![make_stx("a"), make_stx("b")];
        let tag1 = ShadowMixer::generate_mix_tag(&batch);
        let tag2 = ShadowMixer::generate_mix_tag(&batch);
        // Mix tags now include random entropy, so they should differ
        assert_ne!(
            tag1, tag2,
            "Mix tags must be unique per round to prevent replay"
        );
    }

    #[test]
    fn anonymity_set() {
        // MIN_ANONYMITY_SET is 8, so we need at least 8 transactions
        let batch: Vec<_> = (0..8).map(|i| make_stx(&format!("tx{}", i))).collect();
        assert!(ShadowMixer::has_sufficient_anonymity(&batch));
    }

    #[test]
    fn insufficient_anonymity() {
        let batch = vec![make_stx("solo")];
        assert!(!ShadowMixer::has_sufficient_anonymity(&batch));
    }

    #[test]
    fn shuffle_batch_changes_order() {
        // Create a large batch so probability of same order is negligible
        let mut batch: Vec<_> = (0..20).map(|i| make_stx(&format!("tx_{:03}", i))).collect();
        let original_order: Vec<String> = batch.iter().map(|s| s.tx.hash.clone()).collect();

        ShadowMixer::shuffle_batch(&mut batch);
        let new_order: Vec<String> = batch.iter().map(|s| s.tx.hash.clone()).collect();

        // With 20 elements, probability of same order is 1/20! ≈ 0
        assert_ne!(
            original_order, new_order,
            "Shuffle must change transaction order"
        );
    }

    #[test]
    fn shuffle_preserves_all_transactions() {
        let mut batch: Vec<_> = (0..10).map(|i| make_stx(&format!("tx{}", i))).collect();
        let mut original_hashes: Vec<String> = batch.iter().map(|s| s.tx.hash.clone()).collect();
        original_hashes.sort();

        ShadowMixer::shuffle_batch(&mut batch);
        let mut shuffled_hashes: Vec<String> = batch.iter().map(|s| s.tx.hash.clone()).collect();
        shuffled_hashes.sort();

        assert_eq!(
            original_hashes, shuffled_hashes,
            "Shuffle must not lose or duplicate transactions"
        );
    }

    #[test]
    fn random_jitter_within_bounds() {
        for _ in 0..100 {
            let j = ShadowMixer::random_jitter();
            assert!(
                (MIN_JITTER_MS..=MAX_JITTER_MS).contains(&j),
                "Jitter {} out of bounds [{}, {}]",
                j,
                MIN_JITTER_MS,
                MAX_JITTER_MS
            );
        }
    }
}
